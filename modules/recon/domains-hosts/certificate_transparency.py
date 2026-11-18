"""
---
name: Certificate Transparency Search (crt.sh)
description: Harvests authentic subdomains and hosts using crt.sh Certificate Transparency logs with live IP and Geolocation resolution.
author: Recon-ng Team
version: '1.2'
query: SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL
---
"""
import json
from recon.core.module import BaseModule
from recon.utils.osint_helpers import is_valid_subdomain, resolve_ip, get_ip_geolocation


class Module(BaseModule):

    def module_run(self, domains):
        for domain in domains:
            self.heading(domain, level=0)
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            try:
                resp = self.request('GET', url)
                if resp.status_code != 200:
                    self.output(f"Failed to fetch certificate logs for {domain} (HTTP {resp.status_code}).")
                    continue
                try:
                    entries = resp.json()
                except Exception:
                    entries = json.loads(resp.text)
                    
                discovered = set()
                for entry in entries:
                    name_value = entry.get('name_value', '')
                    for host in name_value.splitlines():
                        host = host.strip().lower()
                        if is_valid_subdomain(host, domain):
                            discovered.add(host)
                            
                self.output(f"Discovered {len(discovered)} unique subdomains from CT logs. Resolving network data...")
                
                # Limit initial enrichment batch to 100 to ensure fast response
                sorted_hosts = sorted(list(discovered))[:100]
                added = 0
                for host in sorted_hosts:
                    ip = resolve_ip(host)
                    geo = get_ip_geolocation(ip) if ip else None
                    country = geo.get('country') if geo else None
                    region = geo.get('region') if geo else None
                    lat = geo.get('latitude') if geo else None
                    lon = geo.get('longitude') if geo else None
                    notes = geo.get('notes') if geo else None
                    
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
                    added += 1
                    
                self.output(f"Successfully processed and recorded {added} subdomains with Geolocation.")
            except Exception as e:
                self.error(f"Error querying crt.sh: {e}")
