"""
---
name: DNS Infrastructure Enumeration
description: Enumerates DNS MX (mail exchangers), NS (nameservers), TXT (SPF/DMARC), and SOA records, populating hosts and netblocks.
author: Recon-ng Team
version: '1.0'
query: SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL
---
"""
import re
import dns.resolver
from recon.core.module import BaseModule
from recon.utils.osint_helpers import resolve_ip, get_ip_geolocation


class Module(BaseModule):

    def module_run(self, domains):
        for domain in domains:
            self.heading(f"Enumerating DNS records for {domain}", level=0)
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.5
            resolver.lifetime = 2.5

            # 1. MX Records
            try:
                mx_answers = resolver.resolve(domain, 'MX')
                for rdata in mx_answers:
                    mx_host = str(rdata.exchange).rstrip('.').lower()
                    pref = rdata.preference
                    ip = resolve_ip(mx_host)
                    geo = get_ip_geolocation(ip) if ip else None
                    country = geo.get('country') if geo else None
                    region = geo.get('region') if geo else None
                    lat = geo.get('latitude') if geo else None
                    lon = geo.get('longitude') if geo else None
                    notes = f"MX Server (Priority {pref}) | {geo.get('notes') or ''}".strip(' |')

                    self.insert_hosts(
                        host=mx_host,
                        ip_address=ip,
                        region=region,
                        country=country,
                        latitude=lat,
                        longitude=lon,
                        notes=notes
                    )
                    self.output(f"[MX] {mx_host} (Priority: {pref}) -> {ip or 'N/A'}")
            except Exception as e:
                self.output(f"No MX records found or query failed: {e}")

            # 2. NS Records
            try:
                ns_answers = resolver.resolve(domain, 'NS')
                for rdata in ns_answers:
                    ns_host = str(rdata.target).rstrip('.').lower()
                    ip = resolve_ip(ns_host)
                    geo = get_ip_geolocation(ip) if ip else None
                    country = geo.get('country') if geo else None
                    region = geo.get('region') if geo else None
                    lat = geo.get('latitude') if geo else None
                    lon = geo.get('longitude') if geo else None
                    notes = f"Authoritative Nameserver | {geo.get('notes') or ''}".strip(' |')

                    self.insert_hosts(
                        host=ns_host,
                        ip_address=ip,
                        region=region,
                        country=country,
                        latitude=lat,
                        longitude=lon,
                        notes=notes
                    )
                    self.output(f"[NS] {ns_host} -> {ip or 'N/A'}")
            except Exception as e:
                self.output(f"No NS records found or query failed: {e}")

            # 3. TXT Records (SPF / Netblocks / Security verification)
            try:
                txt_answers = resolver.resolve(domain, 'TXT')
                for rdata in txt_answers:
                    txt_val = ''.join([part.decode('utf-8', errors='ignore') for part in rdata.strings])
                    if 'v=spf1' in txt_val:
                        self.output(f"[SPF] {txt_val[:120]}...")
                        # Extract IPv4 CIDR netblocks from SPF
                        for match in re.findall(r'ip4:([0-9\.\/]+)', txt_val):
                            self.insert_netblocks(netblock=match, notes=f"SPF Authorized Mail Range for {domain}")
                            self.output(f"[NETBLOCK] SPF Range: {match}")
            except Exception as e:
                self.output(f"No TXT records found or query failed: {e}")

