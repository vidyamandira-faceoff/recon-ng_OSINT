"""
---
name: HackerTarget Host Search
description: Harvests genuine subdomains and IP addresses from HackerTarget.com API, with automated Geolocation enrichment.
author: Recon-ng Team
version: '1.3'
query: SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL
---
"""
from recon.core.module import BaseModule
from recon.utils.osint_helpers import is_valid_subdomain, resolve_ip, get_ip_geolocation


class Module(BaseModule):

    def module_run(self, domains):
        for domain in domains:
            self.heading(domain, level=0)
            url = 'https://api.hackertarget.com/hostsearch/'
            payload = {'q': domain}
            try:
                resp = self.request('GET', url, params=payload)
                if resp.status_code != 200 or not resp.text.strip():
                    self.output(f"No results or non-200 response for {domain}.")
                    continue
                text = resp.text.strip()
                if 'error check your api count' in text.lower():
                    self.error('HackerTarget API free query limit reached. Trying other modules.')
                    continue
                if 'no records' in text.lower():
                    self.output(f"No host records found for {domain}.")
                    continue
                    
                count = 0
                for line in text.splitlines():
                    if ',' in line:
                        parts = line.strip().split(',', 1)
                        host = parts[0].strip().lower()
                        ip = parts[1].strip() if len(parts) > 1 else None
                        
                        if not is_valid_subdomain(host, domain):
                            continue
                            
                        if not ip:
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
                        count += 1
                        
                self.output(f"Found and recorded {count} subdomains for {domain}.")
            except Exception as e:
                self.error(f"Error querying HackerTarget: {e}")
