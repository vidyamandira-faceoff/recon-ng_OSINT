"""
Robust OSINT Reconnaissance Engine for Recon-ng
Orchestrates multi-source subdomain discovery, DNS records, WHOIS/contacts,
IP Geolocation, and live service port scanning.
"""
import io
import json
import re
import socket
import ssl
import sys
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver

_GEO_CACHE = {}
_RESOLVE_CACHE = {}

COMMON_SUBDOMAINS = [
    'www', 'mail', 'api', 'admin', 'portal', 'vpn', 'remote', 'auth', 'dev',
    'app', 'secure', 'cloud', 'login', 'shop', 'blog', 'support', 'docs',
    'status', 'gateway', 'm', 'mobile', 'cdn', 'test', 'git', 'jira', 'sso',
    'webmail', 'accounts', 'ns1', 'ns2', 'ns3', 'ns4', 'smtp', 'pop', 'imap',
    'ftp', 'pay', 'billing', 'connect', 'dashboard', 'cpanel', 'staging', 'corp',
    'direct', 'mx', 'dns', 'beta', 'service', 'services', 'ws', 'autodiscover'
]

COMMON_PORTS = [
    (80, 'http'),
    (443, 'https'),
    (8080, 'http-alt'),
    (8443, 'https-alt'),
    (22, 'ssh'),
    (25, 'smtp'),
    (21, 'ftp')
]


def resolve_ip(host, timeout=1.5):
    """Resolves host to IPv4 address with caching."""
    if not host:
        return None
    host = host.strip().lower()
    if host in _RESOLVE_CACHE:
        return _RESOLVE_CACHE[host]
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
        _RESOLVE_CACHE[host] = host
        return host
    try:
        ip = socket.gethostbyname(host)
        _RESOLVE_CACHE[host] = ip
        return ip
    except Exception:
        _RESOLVE_CACHE[host] = None
        return None


def get_ip_geo(ip):
    """Fetches real country, city, coordinates, and ISP/ASN notes."""
    if not ip or ip in _GEO_CACHE:
        return _GEO_CACHE.get(ip)

    if ip.startswith(('127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.')):
        res = {'country': 'Local Network', 'region': 'Local', 'lat': None, 'lon': None, 'notes': 'Private IP'}
        _GEO_CACHE[ip] = res
        return res

    url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,isp,org,as"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get('status') == 'success':
                city = data.get('city') or ''
                region_name = data.get('regionName') or ''
                region_str = f"{region_name}, {city}".strip(', ') if region_name or city else None
                org_info = data.get('org') or data.get('isp') or data.get('as') or ''
                res = {
                    'country': data.get('country'),
                    'region': region_str,
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                    'notes': org_info[:100] if org_info else None
                }
                _GEO_CACHE[ip] = res
                return res
    except Exception:
        pass

    _GEO_CACHE[ip] = None
    return None


def probe_port(target_host, target_ip, port, service, timeout=1.5):
    """Attempts socket connection and grabs service/server banner."""
    target = target_ip or target_host
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        banner = None
        if service in ['http', 'http-alt']:
            s.sendall(f"HEAD / HTTP/1.1\r\nHost: {target_host}\r\nUser-Agent: Recon-ng/5.1\r\nConnection: close\r\n\r\n".encode('utf-8'))
            resp = s.recv(1024).decode('utf-8', errors='ignore')
            for line in resp.splitlines():
                if line.lower().startswith('server:'):
                    banner = line.strip()
                    break
            if not banner and resp:
                banner = resp.splitlines()[0][:60]
        elif service in ['https', 'https-alt']:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(s, server_hostname=target_host) as ss:
                    ss.sendall(f"HEAD / HTTP/1.1\r\nHost: {target_host}\r\nUser-Agent: Recon-ng/5.1\r\nConnection: close\r\n\r\n".encode('utf-8'))
                    resp = ss.recv(1024).decode('utf-8', errors='ignore')
                    for line in resp.splitlines():
                        if line.lower().startswith('server:'):
                            banner = line.strip()
                            break
                    if not banner and resp:
                        banner = resp.splitlines()[0][:60]
            except Exception:
                banner = 'HTTPS (TLS Active)'
        elif service in ['ssh', 'ftp', 'smtp']:
            resp = s.recv(256).decode('utf-8', errors='ignore').strip()
            if resp:
                banner = resp[:80]
        s.close()
        return port, service, banner or f"{service.upper()} Active"
    except Exception:
        return None


def harvest_whois_and_physical_addresses(domain):
    """
    Harvests authentic WHOIS data, Registrant / Registrar entities, contact details,
    and real physical registered street addresses from RDAP and authoritative socket WHOIS.
    """
    domain = domain.strip().lower()
    raw_contacts = []
    physical_addresses = []
    registrar_info = {'name': None, 'address': None}

    email_regex = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')

    # 1. RDAP with recursive entity & vCard adr parsing
    try:
        url = f"https://rdap.org/domain/{domain}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        with urllib.request.urlopen(req, timeout=6.0) as resp:
            rdap_data = json.loads(resp.read().decode('utf-8'))

        def extract_vcard(ent, parent_role=None):
            roles = ent.get('roles', [])
            role_str = ', '.join(roles).title() if roles else (parent_role or 'Contact')
            vcard = ent.get('vcardArray', [])
            fn, org, email, phone, adr_str, country = '', '', '', '', '', ''

            if len(vcard) > 1 and isinstance(vcard[1], list):
                for prop in vcard[1]:
                    pname = prop[0]
                    pval = prop[3] if len(prop) > 3 else ''
                    if pname == 'fn' and pval:
                        fn = str(pval).strip()
                    elif pname == 'org' and pval:
                        org = str(pval).strip()
                    elif pname == 'email' and pval:
                        em = str(pval).strip().lower()
                        if email_regex.match(em):
                            email = em
                    elif pname == 'tel' and pval:
                        phone = str(pval).strip().replace('tel:', '')
                    elif pname == 'adr' and isinstance(pval, list):
                        parts = []
                        for x in pval:
                            if isinstance(x, str) and x.strip():
                                parts.append(x.strip())
                            elif isinstance(x, list):
                                for sub in x:
                                    if isinstance(sub, str) and sub.strip():
                                        parts.append(sub.strip())
                        cc = prop[1].get('cc', '') if len(prop) > 1 and isinstance(prop[1], dict) else ''
                        if cc and cc not in parts:
                            parts.append(cc)
                        adr_str = ', '.join(parts)
                        country = cc

            entity_name = fn or org or (f"{role_str} Entity" if email or adr_str else '')
            if entity_name:
                raw_contacts.append({
                    'name': entity_name,
                    'organization': org or entity_name,
                    'role': role_str,
                    'email': email,
                    'phone': phone,
                    'address': adr_str,
                    'country': country,
                    'source': 'RDAP'
                })
                # ONLY record registrant address as the physical location of the target domain
                is_registrant = any('registrant' in r.lower() for r in roles) or 'registrant' in role_str.lower()
                if adr_str and is_registrant:
                    physical_addresses.append({
                        'address': adr_str,
                        'entity': entity_name,
                        'role': 'Registrant'
                    })
                if 'registrar' in role_str.lower() and not registrar_info['name']:
                    registrar_info['name'] = entity_name
                    registrar_info['address'] = adr_str

            for sub_ent in ent.get('entities', []):
                extract_vcard(sub_ent, parent_role=role_str)

        for ent in rdap_data.get('entities', []):
            extract_vcard(ent)
    except Exception:
        pass

    # 2. Authoritative Socket WHOIS (port 43) query
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4.0)
        s.connect(('whois.iana.org', 43))
        s.send((domain + '\r\n').encode('utf-8'))
        iana_res = b''
        while True:
            d = s.recv(4096)
            if not d: break
            iana_res += d
        s.close()

        tld_server = None
        for line in iana_res.decode('utf-8', errors='ignore').splitlines():
            if line.lower().startswith(('whois:', 'refer:')):
                tld_server = line.split(':', 1)[1].strip()
                break
        if not tld_server:
            tld = domain.split('.')[-1]
            tld_server = f"whois.nic.{tld}"

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4.0)
        s.connect((tld_server, 43))
        q = f"domain {domain}\r\n" if 'verisign' in tld_server else f"{domain}\r\n"
        s.send(q.encode('utf-8'))
        tld_res = b''
        while True:
            d = s.recv(4096)
            if not d: break
            tld_res += d
        s.close()
        whois_full = tld_res.decode('utf-8', errors='ignore')

        reg_server = None
        for line in whois_full.splitlines():
            if 'registrar whois server:' in line.lower():
                reg_server = line.split(':', 1)[1].strip()
                break
        if reg_server and reg_server != tld_server:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4.0)
                s.connect((reg_server, 43))
                s.send((domain + '\r\n').encode('utf-8'))
                reg_res = b''
                while True:
                    d = s.recv(4096)
                    if not d: break
                    reg_res += d
                s.close()
                whois_full += '\n' + reg_res.decode('utf-8', errors='ignore')
            except Exception:
                pass

        data_map = {}
        for line in whois_full.splitlines():
            if ':' in line:
                k, v = line.split(':', 1)
                k = k.strip().lower()
                v = v.strip()
                if v and 'redacted' not in v.lower() and 'please query' not in v.lower():
                    if k not in data_map: data_map[k] = v

        r_street = data_map.get('registrant street', '')
        r_city = data_map.get('registrant city', '')
        r_state = data_map.get('registrant state/province', '')
        r_zip = data_map.get('registrant postal code', '')
        r_cc = data_map.get('registrant country', '')
        r_org = data_map.get('registrant organization', '') or data_map.get('registrant name', '')

        reg_parts = [p for p in [r_street, r_city, r_state, r_zip, r_cc] if p]
        if reg_parts:
            full_addr = ', '.join(reg_parts)
            physical_addresses.append({
                'address': full_addr,
                'entity': r_org or f"{domain} Registrant",
                'role': 'Registrant'
            })
            r_email = data_map.get('registrant email', '').strip()
            if not email_regex.match(r_email):
                r_email = ''
            raw_contacts.append({
                'name': r_org or f"{domain} Registrant",
                'organization': r_org,
                'role': 'Registrant',
                'email': r_email,
                'phone': data_map.get('registrant phone', ''),
                'address': full_addr,
                'country': r_cc,
                'source': 'WHOIS'
            })

        rg_street = data_map.get('registrar street', '')
        rg_city = data_map.get('registrar city', '')
        rg_state = data_map.get('registrar state/province', '')
        rg_zip = data_map.get('registrar postal code', '')
        rg_cc = data_map.get('registrar country', '')
        rg_name = data_map.get('registrar', '') or data_map.get('registrar organization', '')

        rg_parts = [p for p in [rg_street, rg_city, rg_state, rg_zip, rg_cc] if p]
        if rg_parts:
            rg_addr = ', '.join(rg_parts)
            if not registrar_info['name']:
                registrar_info['name'] = rg_name
                registrar_info['address'] = rg_addr

        abuse_email = data_map.get('registrar abuse contact email', '').strip()
        if not email_regex.match(abuse_email):
            abuse_email = ''
        abuse_phone = data_map.get('registrar abuse contact phone', '').strip()
        if abuse_email or abuse_phone:
            raw_contacts.append({
                'name': f"{rg_name or 'Registrar'} Abuse",
                'organization': rg_name,
                'role': 'Abuse Contact',
                'email': abuse_email,
                'phone': abuse_phone,
                'address': rg_addr if rg_parts else '',
                'country': rg_cc,
                'source': 'WHOIS'
            })
    except Exception:
        pass

    # 3. Intelligent Consolidation & Deduplication of Contacts
    # Group contacts into standardized OSINT roles: Registrant, Registrar, Abuse Contact
    contacts_by_role = {}
    for c in raw_contacts:
        r_low = c['role'].lower()
        n_low = c['name'].lower()
        
        if 'abuse' in r_low or 'abuse' in n_low:
            cat = 'abuse'
            canonical_role = 'Abuse Contact'
        elif 'registrant' in r_low:
            cat = 'registrant'
            canonical_role = 'Registrant'
        elif 'registrar' in r_low:
            cat = 'registrar'
            canonical_role = 'Registrar'
        elif 'admin' in r_low:
            cat = 'admin'
            canonical_role = 'Administrative Contact'
        elif 'tech' in r_low:
            cat = 'tech'
            canonical_role = 'Technical Contact'
        else:
            cat = f"other_{c['name'].lower()}"
            canonical_role = c['role']

        if cat not in contacts_by_role:
            contacts_by_role[cat] = {
                'name': c['name'],
                'organization': c['organization'],
                'role': canonical_role,
                'email': c['email'] if email_regex.match(c.get('email', '')) else '',
                'phone': c['phone'] or '',
                'address': c['address'] or '',
                'country': c.get('country') or '',
                'source': c.get('source', 'OSINT')
            }
        else:
            existing = contacts_by_role[cat]
            if not existing['email'] and email_regex.match(c.get('email', '')):
                existing['email'] = c['email']
            if not existing['phone'] and c.get('phone'):
                existing['phone'] = c['phone']
            if (not existing['address'] or len(c.get('address', '')) > len(existing['address'])) and c.get('address'):
                existing['address'] = c['address']
            if not existing['country'] and c.get('country'):
                existing['country'] = c['country']
            if len(c['name']) > len(existing['name']) and 'Team' not in c['name']:
                existing['name'] = c['name']

    role_order = {'registrant': 1, 'registrar': 2, 'abuse': 3, 'admin': 4, 'tech': 5}
    sorted_cats = sorted(contacts_by_role.keys(), key=lambda k: role_order.get(k, 10))
    final_contacts = [contacts_by_role[k] for k in sorted_cats]

    # Deduplicate physical addresses (Registrant address only)
    unique_addrs = []
    seen_a = set()
    for a in physical_addresses:
        ak = a['address'].strip().lower()
        if ak and ak not in seen_a:
            seen_a.add(ak)
            unique_addrs.append(a)

    return {
        'contacts': final_contacts,
        'physical_addresses': unique_addrs,
        'registrar': registrar_info
    }


def run_full_osint_scan(recon, domain):
    """
    Executes a comprehensive, guaranteed multi-stage OSINT scan across a target domain.
    Directly populates Recon-ng's SQLite tables: hosts, contacts, ports, locations, domains, companies.
    """
    domain = domain.strip().lower()
    log_lines = []

    def log(msg):
        log_lines.append(msg)
        print(msg)

    log("============================================================")
    log(f"  LAUNCHING FULL OSINT RECONNAISSANCE: {domain.upper()}")
    log("============================================================\n")

    # 1. Insert Target Domain
    try:
        recon.insert_domains(domain=domain, notes="Target of Full OSINT Scan")
        log(f"[*] Target registered: {domain}")
    except Exception as e:
        log(f"[!] Warning registering domain: {e}")

    # 2. Stage 1: WHOIS & Physical Address Intelligence
    log("\n[>>> STAGE 1: WHOIS & Physical Address Intelligence <<<]")
    whois_res = harvest_whois_and_physical_addresses(domain)
    contacts_found = 0
    physical_addresses_found = 0

    if whois_res['registrar'].get('name'):
        r_name = whois_res['registrar']['name']
        r_addr = whois_res['registrar'].get('address') or ''
        recon.insert_companies(company=r_name, description=f"Domain Registrar for {domain}" + (f" | Address: {r_addr}" if r_addr else ""))
        log(f"[*] Registrar identified: {r_name}")

    # Record verified physical addresses
    for a in whois_res['physical_addresses']:
        recon.insert_locations(
            street_address=f"[Physical Registered Address] {a['address']}",
            notes=f"{a['entity']} ({a['role']}) for {domain}"
        )
        physical_addresses_found += 1
        log(f" [PHYSICAL ADDRESS] {a['role']} ({a['entity']}): {a['address']}")

    # Record contacts
    for c in whois_res['contacts']:
        recon.insert_contacts(
            first_name=c['name'],
            title=c['role'],
            email=c['email'] or None,
            phone=c['phone'] or None,
            region=c['address'] or None,
            country=c.get('country') or None,
            notes=f"{c['role']} for {domain}" + (f" | Address: {c['address']}" if c.get('address') else "")
        )
        contacts_found += 1
        addr_tag = f" (Address: {c['address']})" if c.get('address') else ""
        log(f" [CONTACT] {c['role']}: {c['name']} | Email: {c['email'] or 'N/A'} | Phone: {c['phone'] or 'N/A'}{addr_tag}")

    log(f"[*] Total contacts harvested: {contacts_found} | Physical addresses identified: {physical_addresses_found}")

    # 3. Stage 2: DNS Infrastructure (A, MX, NS, TXT)
    log("\n[>>> STAGE 2: DNS Infrastructure & Name Servers <<<]")
    discovered_hosts = set()
    discovered_hosts.add(domain)
    discovered_hosts.add(f"www.{domain}")

    # Resolver queries
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    try:
        mx_records = resolver.resolve(domain, 'MX')
        for rdata in mx_records:
            mx_h = str(rdata.exchange).rstrip('.').lower()
            if mx_h == domain or mx_h.endswith('.' + domain):
                discovered_hosts.add(mx_h)
            log(f" [MX] Mail Server: {mx_h} (Priority {rdata.preference})")
    except Exception:
        pass

    try:
        ns_records = resolver.resolve(domain, 'NS')
        for rdata in ns_records:
            ns_h = str(rdata.target).rstrip('.').lower()
            if ns_h == domain or ns_h.endswith('.' + domain):
                discovered_hosts.add(ns_h)
            log(f" [NS] Authoritative Nameserver: {ns_h}")
    except Exception:
        pass

    try:
        txt_records = resolver.resolve(domain, 'TXT')
        for rdata in txt_records:
            txt_str = ''.join([p.decode('utf-8', errors='ignore') for p in rdata.strings])
            if 'v=spf1' in txt_str:
                log(f" [SPF] {txt_str[:90]}...")
                for net in re.findall(r'ip4:([0-9\.\/]+)', txt_str):
                    recon.insert_netblocks(netblock=net, notes=f"SPF Mail Range for {domain}")
    except Exception:
        pass

    # 4. Stage 3: Multi-Source Subdomain Discovery
    log("\n[>>> STAGE 3: Multi-Source Subdomain Discovery <<<]")

    # Source A: HackerTarget Hostsearch API
    try:
        ht_url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        req = urllib.request.Request(ht_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=6.0) as resp:
            text = resp.read().decode('utf-8', errors='ignore')
            if text and 'error' not in text.lower():
                for line in text.splitlines():
                    if ',' in line:
                        h = line.split(',', 1)[0].strip().lower()
                        if h == domain or h.endswith('.' + domain):
                            discovered_hosts.add(h)
    except Exception as e:
        log(f"[!] HackerTarget query note: {e}")

    # Source B: AlienVault OTX Passive DNS
    try:
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        req = urllib.request.Request(otx_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            otx_data = json.loads(resp.read().decode('utf-8'))
            for rec in otx_data.get('passive_dns', []):
                h = rec.get('hostname', '').strip().lower()
                if h == domain or h.endswith('.' + domain):
                    discovered_hosts.add(h)
    except Exception:
        pass

    # Source C: Active DNS Probing of Common Subdomains
    def probe_sub(sub):
        cand = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(cand)
            return cand, ip
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = [executor.submit(probe_sub, sub) for sub in COMMON_SUBDOMAINS]
        for f in as_completed(futures):
            res = f.result()
            if res:
                h, ip = res
                if h == domain or h.endswith('.' + domain):
                    discovered_hosts.add(h)
                    _RESOLVE_CACHE[h] = ip

    # Strictly retain only valid subdomains of the target domain
    target_hosts = [h for h in sorted(list(discovered_hosts)) if h == domain or h.endswith('.' + domain)]
    log(f"[*] Total unique verified subdomains discovered: {len(target_hosts)}")

    # 5. Stage 4: Network Geolocation & Host Database Population
    log("\n[>>> STAGE 4: Resolving IPs & Server Hosting Infrastructure <<<]")
    hosts_recorded = 0
    seen_datacenters = set()

    for h in target_hosts:
        ip = resolve_ip(h)
        geo = get_ip_geo(ip) if ip else None
        country = geo.get('country') if geo else None
        region = geo.get('region') if geo else None
        lat = geo.get('lat') if geo else None
        lon = geo.get('lon') if geo else None
        notes = geo.get('notes') if geo else None

        recon.insert_hosts(
            host=h,
            ip_address=ip,
            region=region,
            country=country,
            latitude=lat,
            longitude=lon,
            notes=notes
        )
        if lat and lon and geo:
            # Group datacenters by geographical region & ISP network so each real datacenter is recorded once
            dc_key = (country, region, notes)
            if dc_key not in seen_datacenters:
                seen_datacenters.add(dc_key)
                loc_desc = f"{region or ''}, {country or ''}".strip(', ')
                recon.insert_locations(
                    latitude=lat,
                    longitude=lon,
                    street_address=f"[Server Datacenter] {loc_desc}",
                    notes=f"Hosting Infrastructure ({notes or 'ISP'}) for {h} ({ip}) | {domain}"
                )
        hosts_recorded += 1
        log(f" [HOST] {h:35} -> {ip or 'N/A':15} | {country or 'Unknown'}")

    log(f"[*] Successfully recorded {hosts_recorded} hosts with IP & Infrastructure details.")

    # 6. Stage 5: Live Service & Port Scanning
    log("\n[>>> STAGE 5: Live Port & Service Scanner <<<]")
    ports_found = 0

    # Scan only hosts belonging strictly to domain, prioritizing unique IPs
    scan_targets = []
    seen_ips = set()

    root_ip = resolve_ip(domain)
    if root_ip:
        scan_targets.append((domain, root_ip))
        seen_ips.add(root_ip)

    if f"www.{domain}" in target_hosts:
        www_ip = resolve_ip(f"www.{domain}")
        if www_ip and www_ip not in seen_ips:
            scan_targets.append((f"www.{domain}", www_ip))
            seen_ips.add(www_ip)

    for h in target_hosts:
        if h in [domain, f"www.{domain}"]:
            continue
        h_ip = resolve_ip(h)
        if h_ip:
            if h_ip not in seen_ips or len(scan_targets) < 5:
                scan_targets.append((h, h_ip))
                seen_ips.add(h_ip)
        if len(scan_targets) >= 8:
            break

    for host_name, host_ip in scan_targets:
        if not host_ip:
            continue
        for port, service in COMMON_PORTS:
            res = probe_port(host_name, host_ip, port, service, timeout=1.2)
            if res:
                p, s_name, banner = res
                recon.insert_ports(
                    ip_address=host_ip,
                    host=host_name,
                    port=p,
                    protocol='tcp',
                    banner=banner,
                    notes=s_name
                )
                ports_found += 1
                log(f" [PORT] {host_name}:{p}/tcp ({s_name}) -> {banner}")

    log(f"[*] Port scan complete: {ports_found} active service ports identified.")

    # Record into scan_history
    try:
        recon.query('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE,
                timestamp TEXT,
                hosts_count INTEGER DEFAULT 0,
                contacts_count INTEGER DEFAULT 0,
                ports_count INTEGER DEFAULT 0,
                locations_count INTEGER DEFAULT 0
            )
        ''')
        import datetime
        now_str = datetime.datetime.now().strftime('%b %d, %Y - %I:%M %p')
        loc_count = len(recon.query("SELECT * FROM locations WHERE notes LIKE ? OR street_address LIKE ?", (f'%{domain}%', f'%{domain}%')))
        recon.query(
            "INSERT OR REPLACE INTO scan_history (domain, timestamp, hosts_count, contacts_count, ports_count, locations_count) VALUES (?, ?, ?, ?, ?, ?)",
            (domain, now_str, hosts_recorded, contacts_found, ports_found, loc_count)
        )
    except Exception as e:
        log(f"[!] Warning recording scan history: {e}")

    loc_final = len(recon.query("SELECT * FROM locations WHERE notes LIKE ? OR street_address LIKE ?", (f'%{domain}%', f'%{domain}%')))
    log("\n============================================================")
    log(f"  RECONNAISSANCE FINISHED FOR {domain.upper()}")
    log(f"  Summary: {hosts_recorded} Hosts | {contacts_found} Contacts | {ports_found} Ports | {loc_final} Locations")
    log("============================================================\n")

    return {
        'domain': domain,
        'status': 'finished',
        'counts': {
            'hosts': hosts_recorded,
            'contacts': contacts_found,
            'ports': ports_found,
            'locations': loc_final
        },
        'output': '\n'.join(log_lines)
    }

