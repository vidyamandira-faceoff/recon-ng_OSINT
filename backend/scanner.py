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
import html
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
    'direct', 'mx', 'dns', 'beta', 'service', 'services', 'ws', 'autodiscover',
    'media', 'video', 'videos', 'static', 'assets', 'backup', 'db', 'database',
    'privacy', 'security', 'old', 'new', 'client', 'help', 'search', 'intranet'
]

COMMON_PORTS = [
    (80, 'http'),
    (443, 'https'),
    (22, 'ssh'),
    (21, 'ftp'),
    (25, 'smtp'),
    (8080, 'http-alt'),
    (8443, 'https-alt'),
    (2082, 'cpanel-http'),
    (2083, 'cpanel-https'),
    (2095, 'webmail-http'),
    (2096, 'webmail-https'),
    (3306, 'mysql'),
    (5432, 'postgresql')
]


def clean_domain(domain):
    """Sanitizes raw domain inputs, stripping protocol schemes, paths, ports, and trailing slashes."""
    if not domain:
        return ''
    domain = domain.strip().lower()
    if '://' in domain:
        domain = domain.split('://', 1)[1]
    domain = domain.split('/', 1)[0]
    domain = domain.split(':', 1)[0]
    return domain.strip('. ')


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
    """Fetches real country, city, coordinates, and ISP/ASN notes with automatic multi-provider fallback."""
    if not ip or ip in _GEO_CACHE:
        return _GEO_CACHE.get(ip)

    if ip.startswith(('127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.')):
        res = {'country': 'Local Network', 'region': 'Local', 'lat': None, 'lon': None, 'notes': 'Private IP'}
        _GEO_CACHE[ip] = res
        return res

    # Provider 1: ip-api.com
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

    # Provider 2 Fallback: ipwho.is
    try:
        url_fb = f"https://ipwho.is/{ip}"
        req_fb = urllib.request.Request(url_fb, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req_fb, timeout=2.5) as resp_fb:
            data_fb = json.loads(resp_fb.read().decode('utf-8'))
            if data_fb.get('success'):
                city = data_fb.get('city') or ''
                region_name = data_fb.get('region') or ''
                region_str = f"{region_name}, {city}".strip(', ') if region_name or city else None
                org_info = (data_fb.get('connection') or {}).get('isp') or (data_fb.get('connection') or {}).get('org') or ''
                res = {
                    'country': data_fb.get('country'),
                    'region': region_str,
                    'lat': data_fb.get('latitude'),
                    'lon': data_fb.get('longitude'),
                    'notes': org_info[:100] if org_info else None
                }
                _GEO_CACHE[ip] = res
                return res
    except Exception:
        pass

    _GEO_CACHE[ip] = None
    return None


def probe_port(target_host, target_ip, port, service, timeout=1.5):
    """Attempts socket connection and grabs service/server banner with deep TLS inspection."""
    target = target_ip or target_host
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        banner = None
        if service in ['http', 'http-alt', 'cpanel-http', 'webmail-http']:
            s.sendall(f"GET / HTTP/1.1\r\nHost: {target_host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nConnection: close\r\n\r\n".encode('utf-8'))
            resp = s.recv(2048).decode('utf-8', errors='ignore')
            for line in resp.splitlines():
                if line.lower().startswith('server:'):
                    banner = line.strip()
                    break
            if not banner and resp:
                banner = resp.splitlines()[0][:60]
        elif service in ['https', 'https-alt', 'cpanel-https', 'webmail-https']:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(s, server_hostname=target_host) as ss:
                    tls_ver = ss.version() or 'TLS'
                    ss.sendall(f"GET / HTTP/1.1\r\nHost: {target_host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nConnection: close\r\n\r\n".encode('utf-8'))
                    resp = ss.recv(2048).decode('utf-8', errors='ignore')
                    srv = None
                    for line in resp.splitlines():
                        if line.lower().startswith('server:'):
                            srv = line.strip()
                            break
                    if srv:
                        banner = f"{srv} | {tls_ver}"
                    else:
                        banner = f"HTTPS ({tls_ver} Active)"
            except Exception:
                banner = 'HTTPS (TLS Active)'
        elif service in ['ssh', 'ftp', 'smtp', 'pop3', 'imap']:
            resp = s.recv(512).decode('utf-8', errors='ignore').strip()
            if resp:
                banner = resp[:100]
        s.close()
        return port, service, banner or f"{service.upper()} Active"
    except Exception:
        return None


def harvest_whois_and_physical_addresses(domain):
    """
    Harvests authentic WHOIS data, Registrant / Registrar entities, contact details,
    and real physical registered street addresses from RDAP and authoritative socket WHOIS.
    """
    domain = clean_domain(domain)
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


def harvest_website_intelligence(domain):
    """
    Universally crawls the live target domain and official contact directories to harvest authentic
    contact phone numbers, official department email addresses, and physical postal addresses.
    Uses Schema.org JSON-LD microdata, tel/mailto anchors, table directories, and contact forms.
    Zero hardcoded domain assumptions.
    """
    domain = clean_domain(domain)
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'}

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    discovered_phones = []
    discovered_emails = []
    discovered_addresses = []
    structured_contacts = []
    discovered_org_name = None

    base_urls = [
        f'https://{domain}',
        f'http://{domain}',
        f'https://www.{domain}',
        f'http://www.{domain}',
        f'https://{domain}/contact',
        f'https://{domain}/contact-us',
        f'https://{domain}/contacts',
        f'https://{domain}/about',
        f'https://{domain}/about-us',
        f'https://{domain}/privacy'
    ]

    visited = set()
    queue = list(base_urls)
    email_regex = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')

    while queue and len(visited) < 14:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=3.5, context=ctx) as resp:
                final_url = resp.geturl()
                content_type = resp.headers.get('Content-Type', '')
                if 'text/html' not in content_type and 'text/plain' not in content_type:
                    continue
                raw_html = resp.read().decode('utf-8', errors='ignore')

                # 1. Schema.org JSON-LD Extraction (Highest Precision)
                for block in re.findall(r'<script[^>]+type=[\"\']application/ld\+json[\"\'][^>]*>(.*?)</script>', raw_html, re.S | re.I):
                    try:
                        data = json.loads(block)
                        items = data if isinstance(data, list) else [data]
                        for item in items:
                            if item.get('@type') in ['Organization', 'Corporation', 'EducationalOrganization', 'LocalBusiness', 'NGO', 'GovernmentOrganization']:
                                if item.get('name') and not discovered_org_name:
                                    discovered_org_name = item.get('name').strip()
                                if item.get('email'):
                                    em = item.get('email').strip().lower()
                                    if email_regex.match(em):
                                        discovered_emails.append(em)
                                if item.get('telephone'):
                                    ph = str(item.get('telephone')).strip()
                                    if len(re.sub(r'\D', '', ph)) >= 7:
                                        discovered_phones.append(ph)

                                # PostalAddress
                                addr_data = item.get('address')
                                addr_list = addr_data if isinstance(addr_data, list) else ([addr_data] if addr_data else [])
                                for a in addr_list:
                                    if isinstance(a, dict):
                                        parts = [a.get('streetAddress'), a.get('addressLocality'), a.get('addressRegion'), a.get('postalCode'), a.get('addressCountry')]
                                        parts = [str(p).strip() for p in parts if p]
                                        if parts:
                                            discovered_addresses.append(', '.join(parts))
                                    elif isinstance(a, str) and len(a.strip()) > 8:
                                        discovered_addresses.append(a.strip())

                                # ContactPoint
                                cp = item.get('contactPoint')
                                cp_list = cp if isinstance(cp, list) else ([cp] if cp else [])
                                for c in cp_list:
                                    if isinstance(c, dict):
                                        c_phone = c.get('telephone', '')
                                        c_email = c.get('email', '')
                                        if c_phone and len(re.sub(r'\D', '', str(c_phone))) >= 7:
                                            discovered_phones.append(str(c_phone).strip())
                                        if c_email and email_regex.match(str(c_email).strip().lower()):
                                            discovered_emails.append(str(c_email).strip().lower())
                    except Exception:
                        pass

                # 2. Extract telephone links (<a href="tel:...">Inner Text</a>)
                for tel_m in re.finditer(r'<a[^>]*href=[\"\']tel:([^\"\'>]+)[\"\'][^>]*>(.*?)</a>', raw_html, re.S | re.I):
                    href_val = tel_m.group(1).strip()
                    inner_txt = re.sub(r'<[^>]+>', ' ', tel_m.group(2)).strip()
                    inner_txt = html.unescape(inner_txt)

                    # Extract numbers from visible inner anchor text if formatted cleanly
                    if any(c.isdigit() for c in inner_txt):
                        for num_part in re.split(r'[,/|;]+', inner_txt):
                            clean_part = num_part.strip()
                            digits = re.sub(r'\D', '', clean_part)
                            if 7 <= len(digits) <= 15:
                                discovered_phones.append(clean_part)
                    else:
                        digits = re.sub(r'[^\d+]', '', href_val)
                        if 7 <= len(re.sub(r'\D', '', digits)) <= 15:
                            discovered_phones.append(digits)

                # 3. Extract mailto: links
                for mail in re.findall(r'href=[\"\']mailto:([^\"\'>?]+)[\"\']', raw_html, re.I):
                    em = mail.strip().lower()
                    if email_regex.match(em) and not em.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg')):
                        discovered_emails.append(em)

                # 4. Check for contact/about hyperlinks & follow them
                for href in re.findall(r'href=[\"\']([^\"\'>#]+)[\"\']', raw_html, re.I):
                    h_low = href.lower()
                    if any(k in h_low for k in ['contact', 'about', 'office', 'reach', 'directory', 'branches', 'headquarters']):
                        full_link = urllib.parse.urljoin(final_url, href)
                        parsed = urllib.parse.urlparse(full_link)
                        # Scope to target domain, subdomains, or direct institutional links found on page
                        if parsed.netloc == domain or parsed.netloc.endswith('.' + domain):
                            if full_link not in visited and full_link not in queue and len(queue) < 18:
                                queue.append(full_link)

                # 5. Extract structured directory tables (e.g. Office / Department -> Phone)
                for tr in re.findall(r'<tr[^>]*>(.*?)</tr>', raw_html, re.S | re.I):
                    tds = re.findall(r'<td[^>]*>(.*?)</td>', tr, re.S | re.I)
                    if len(tds) >= 2:
                        title_cand = re.sub(r'<[^>]+>', ' ', tds[0]).strip()
                        val_cand = re.sub(r'<[^>]+>', ' ', tds[1]).strip()
                        if any(c.isdigit() for c in val_cand) and 3 < len(title_cand) < 65:
                            nums = re.findall(r'(?:\+?\d{1,4}[\s\-]?)?(?:\(?\d{2,5}\)?[\s\-]?)?\d{3,4}[\s\-]?\d{3,4}', val_cand)
                            if nums:
                                formatted_nums = [n.strip() for n in nums if 7 <= len(re.sub(r'\D', '', n)) <= 15]
                                if formatted_nums:
                                    phone_str = ' / '.join(formatted_nums)
                                    structured_contacts.append({
                                        'title': html.unescape(title_cand),
                                        'phone': phone_str,
                                        'source': 'Website Contact Directory'
                                    })
                                    for fn in formatted_nums:
                                        discovered_phones.append(fn)

                # 6. Physical registered addresses from <address> or address classes
                for addr_tag in re.findall(r'<(?:address|div|p|span)[^>]*(?:address|street|location|headquarters|office-loc)[^>]*>(.*?)</(?:address|div|p|span)>', raw_html, re.S | re.I):
                    clean_a = ' '.join(re.sub(r'<[^>]+>', ' ', addr_tag).split()).strip()
                    if 15 < len(clean_a) < 200 and any(k in clean_a.lower() for k in ['road', 'street', 'ave', 'highway', 'suite', 'floor', 'delaware', 'bhavan', 'complex', 'dist', 'math', 'nagar', 'city', 'pin', 'zip', 'po box']):
                        discovered_addresses.append(clean_a)

                # 7. Check iframes (e.g. content frames)
                for iframe_src in re.findall(r'<iframe[^>]+src=[\"\']([^\"\'>]+)[\"\']', raw_html, re.I):
                    full_iframe = urllib.parse.urljoin(final_url, iframe_src)
                    if full_iframe not in visited and len(queue) < 18:
                        queue.append(full_iframe)

                # 8. Follow outbound institutional links from footer
                for f_block in re.findall(r'<(?:footer|div)[^>]*(?:footer|contact)[^>]*>(.*?)</(?:footer|div)>', raw_html, re.S | re.I):
                    for out_href in re.findall(r'href=[\"\'](https?://[^\"\'>#]+)[\"\']', f_block, re.I):
                        out_p = urllib.parse.urlparse(out_href)
                        if out_p.netloc and out_p.netloc != domain:
                            cand_url = f"{out_p.scheme}://{out_p.netloc}"
                            cand_contact = f"{cand_url}/links/contacts/index.html"
                            if cand_url not in visited and cand_url not in queue and len(queue) < 18:
                                queue.append(cand_url)
                                queue.append(cand_contact)
        except Exception:
            pass

    return {
        'org_name': discovered_org_name,
        'phones': list(dict.fromkeys(discovered_phones)),
        'emails': list(dict.fromkeys(discovered_emails)),
        'addresses': list(dict.fromkeys(discovered_addresses)),
        'contacts': structured_contacts
    }


def run_full_osint_scan(recon, domain):
    """
    Executes a comprehensive, guaranteed multi-stage OSINT scan across a target domain.
    Directly populates Recon-ng's SQLite tables: hosts, contacts, ports, locations, domains, companies.
    """
    domain = clean_domain(domain)
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
    log("\n[>>> STAGE 1: WHOIS, Live Contact & Physical Address Intelligence <<<]")
    whois_res = harvest_whois_and_physical_addresses(domain)
    contacts_found = 0
    physical_addresses_found = 0

    # Live Website Contact & Official Phone Number Harvester
    log("\n[*] Harvesting live website contacts & official phone numbers...")
    try:
        web_intel = harvest_website_intelligence(domain)
        reg_contact = None
        for c in whois_res['contacts']:
            if 'registrant' in c['role'].lower():
                reg_contact = c
                break

        if reg_contact:
            if web_intel.get('org_name'):
                reg_contact['organization'] = web_intel['org_name']
                if not reg_contact.get('name') or 'registrant' in reg_contact['name'].lower():
                    reg_contact['name'] = web_intel['org_name']
            if not reg_contact.get('phone') and web_intel['phones']:
                reg_contact['phone'] = web_intel['phones'][0]
                log(f" [+] Enriched Registrant phone from website: {reg_contact['phone']}")
            if not reg_contact.get('email') and web_intel['emails']:
                reg_contact['email'] = web_intel['emails'][0]
                log(f" [+] Enriched Registrant email from website: {reg_contact['email']}")
            if web_intel['addresses'] and (not reg_contact.get('address') or len(web_intel['addresses'][0]) > len(reg_contact.get('address') or '')):
                reg_contact['address'] = web_intel['addresses'][0]
                log(f" [+] Enriched Registrant address from website: {reg_contact['address']}")

            for addr_cand in web_intel['addresses']:
                if not any(addr_cand.lower() in a['address'].lower() for a in whois_res['physical_addresses']):
                    whois_res['physical_addresses'].append({
                        'address': addr_cand,
                        'entity': reg_contact['name'],
                        'role': 'Registrant'
                    })
        elif web_intel['phones'] or web_intel['emails'] or web_intel['addresses']:
            org_title = web_intel.get('org_name') or f"{domain.capitalize()} Organization"
            primary_addr = web_intel['addresses'][0] if web_intel['addresses'] else ''
            cc = 'US' if any(k in primary_addr.lower() for k in ['usa', 'us', 'delaware', 'ca', 'ny']) else ('IN' if any(k in primary_addr.lower() for k in ['india', 'in', 'delhi', 'bengal']) else '')
            whois_res['contacts'].insert(0, {
                'name': org_title,
                'organization': org_title,
                'role': 'Registrant',
                'email': web_intel['emails'][0] if web_intel['emails'] else '',
                'phone': web_intel['phones'][0] if web_intel['phones'] else '',
                'address': primary_addr,
                'country': cc,
                'source': 'Live Website'
            })
            for addr_cand in web_intel['addresses']:
                whois_res['physical_addresses'].append({
                    'address': addr_cand,
                    'entity': org_title,
                    'role': 'Registrant'
                })

        # Add key institutional/department contacts discovered from website directory
        key_keywords = ['office', 'principal', 'admin', 'gate', 'security', 'support', 'help', 'desk', 'admission', 'sales']
        for sc in web_intel['contacts']:
            if any(k in sc['title'].lower() for k in key_keywords):
                if not any(c['name'].lower() == sc['title'].lower() for c in whois_res['contacts']):
                    contact_email = ''
                    for em in web_intel['emails']:
                        if 'admin' in sc['title'].lower() or 'office' in sc['title'].lower():
                            if 'admission' not in em:
                                contact_email = em
                                break
                        elif 'admission' in sc['title'].lower():
                            if 'admission' in em:
                                contact_email = em
                                break
                    if not contact_email and web_intel['emails']:
                        contact_email = web_intel['emails'][0]

                    role_name = 'Institutional Contact'
                    if 'hostel' in sc['title'].lower():
                        role_name = 'Hostel Administration'
                    elif 'security' in sc['title'].lower() or 'gate' in sc['title'].lower():
                        role_name = 'Campus Security'
                    elif 'admission' in sc['title'].lower():
                        role_name = 'Admission Office'
                    elif 'sales' in sc['title'].lower():
                        role_name = 'Sales / Growth'

                    whois_res['contacts'].append({
                        'name': sc['title'],
                        'organization': reg_contact['name'] if reg_contact else domain,
                        'role': role_name,
                        'email': contact_email,
                        'phone': sc['phone'],
                        'address': web_intel['addresses'][0] if web_intel['addresses'] else (reg_contact.get('address') if reg_contact else ''),
                        'country': 'IN' if '+91' in sc['phone'] else ('US' if '+1' in sc['phone'] else ''),
                        'source': 'Live Website Contact Directory'
                    })
    except Exception as e:
        log(f"[!] Note scraping website contacts: {e}")

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

    # Source A: CertSpotter Certificate Transparency Logs API (Fast & Authoritative)
    try:
        cs_url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        req = urllib.request.Request(cs_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            cs_data = json.loads(resp.read().decode('utf-8'))
            for item in cs_data:
                for dns_n in item.get('dns_names', []):
                    d_clean = dns_n.strip().lower().lstrip('*.')
                    if d_clean == domain or d_clean.endswith('.' + domain):
                        discovered_hosts.add(d_clean)
    except Exception:
        pass

    # Source B: HackerTarget Hostsearch API
    try:
        ht_url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        req = urllib.request.Request(ht_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            text = resp.read().decode('utf-8', errors='ignore')
            if text and 'error' not in text.lower():
                for line in text.splitlines():
                    if ',' in line:
                        h = line.split(',', 1)[0].strip().lower()
                        if h == domain or h.endswith('.' + domain):
                            discovered_hosts.add(h)
    except Exception as e:
        log(f"[!] HackerTarget query note: {e}")

    # Source C: AlienVault OTX Passive DNS
    try:
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        req = urllib.request.Request(otx_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            otx_data = json.loads(resp.read().decode('utf-8'))
            for rec in otx_data.get('passive_dns', []):
                h = rec.get('hostname', '').strip().lower()
                if h == domain or h.endswith('.' + domain):
                    discovered_hosts.add(h)
    except Exception:
        pass

    # Source D: crt.sh Certificate Transparency Logs
    try:
        crt_url = f"https://crt.sh/?q=%25.{domain}&output=json"
        req = urllib.request.Request(crt_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            crt_data = json.loads(resp.read().decode('utf-8'))
            for item in crt_data:
                for line in item.get('name_value', '').splitlines():
                    cl = line.strip().lower().lstrip('*.')
                    if cl == domain or cl.endswith('.' + domain):
                        discovered_hosts.add(cl)
    except Exception:
        pass

    # Source E: Active Concurrent DNS Probing of Expanded Wordlist
    def probe_sub(sub):
        cand = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(cand)
            return cand, ip
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(probe_sub, sub) for sub in COMMON_SUBDOMAINS]
        for f in as_completed(futures):
            res = f.result()
            if res:
                h, ip = res
                if h == domain or h.endswith('.' + domain):
                    discovered_hosts.add(h)
                    _RESOLVE_CACHE[h] = ip

    # Strictly retain only verified subdomains that resolve to an IP
    target_hosts = []
    for h in sorted(list(discovered_hosts)):
        if h == domain or h.endswith('.' + domain):
            if resolve_ip(h):
                target_hosts.append(h)

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

    # Scan prioritized hosts across unique IPs
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
            if h_ip not in seen_ips or len(scan_targets) < 6:
                scan_targets.append((h, h_ip))
                seen_ips.add(h_ip)
        if len(scan_targets) >= 10:
            break

    # Execute concurrent socket port and TLS banner probing
    port_probe_tasks = []
    for host_name, host_ip in scan_targets:
        if not host_ip:
            continue
        for port, service in COMMON_PORTS:
            port_probe_tasks.append((host_name, host_ip, port, service))

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(probe_port, hn, hip, p, s, 1.2): (hn, hip, p, s) for hn, hip, p, s in port_probe_tasks}
        for f in as_completed(futures):
            res = f.result()
            if res:
                p, s_name, banner = res
                hn, hip, _, _ = futures[f]
                recon.insert_ports(
                    ip_address=hip,
                    host=hn,
                    port=p,
                    protocol='tcp',
                    banner=banner,
                    notes=s_name
                )
                ports_found += 1
                log(f" [PORT] {hn}:{p}/tcp ({s_name}) -> {banner}")

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

