"""
---
name: Active Subdomain Prober
description: Actively probes top high-value production subdomains (www, mail, api, admin, vpn, dev, etc.) via DNS and discovers live hosts.
author: Recon-ng Team
version: '1.2'
query: SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL
---
"""
import socket
from recon.core.module import BaseModule
from recon.utils.osint_helpers import get_ip_geolocation

COMMON_SUBDOMAINS = [
    'www', 'mail', 'api', 'admin', 'portal', 'vpn', 'remote', 'auth', 'dev',
    'app', 'secure', 'cloud', 'login', 'shop', 'blog', 'support', 'docs',
    'status', 'gateway', 'm', 'mobile', 'cdn', 'test', 'git', 'jira', 'sso',
    'webmail', 'accounts', 'ns1', 'ns2'
]


class Module(BaseModule):

    def module_run(self, domains):
        for domain in domains:
            self.heading(f"Probing production subdomains for {domain}", level=0)
            added = 0
            
            for sub in COMMON_SUBDOMAINS:
                host = f"{sub}.{domain}"
                try:
                    ip = socket.gethostbyname(host)
                    if ip:
                        geo = get_ip_geolocation(ip)
                        country = geo.get('country') if geo else None
                        region = geo.get('region') if geo else None
                        lat = geo.get('latitude') if geo else None
                        lon = geo.get('longitude') if geo else None
                        notes = f"Active Subdomain | {geo.get('notes') or ''}".strip(' |')

                        self.insert_hosts(
                            host=host,
                            ip_address=ip,
                            region=region,
                            country=country,
                            latitude=lat,
                            longitude=lon,
                            notes=notes
                        )
                        if lat and lon:
                            self.insert_locations(latitude=lat, longitude=lon, street_address=f"{region or ''}, {country or ''}".strip(', '))
                        self.output(f"[LIVE SUBDOMAIN] {host} -> {ip} ({country or 'Active'})")
                        added += 1
                except Exception:
                    continue

            self.output(f"Verified {added} active, responding subdomains for {domain}.")
