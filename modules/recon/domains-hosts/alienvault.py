"""
---
name: AlienVault OTX Passive DNS
description: Harvests real-world subdomains and historical IP resolutions from AlienVault Open Threat Exchange.
author: Recon-ng Team
version: '1.0'
query: SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL
---
"""
from recon.core.module import BaseModule
from recon.utils.osint_helpers import is_valid_subdomain, resolve_ip, get_ip_geolocation


class Module(BaseModule):

    def module_run(self, domains):
        for domain in domains:
            self.heading(domain, level=0)
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            try:
                resp = self.request('GET', url)
                if resp.status_code != 200:
                    self.output(f"AlienVault OTX returned HTTP {resp.status_code} for {domain}.")
                    continue
                data = resp.json()
                passive_records = data.get('passive_dns', [])
                if not passive_records:
                    self.output(f"No passive DNS records found for {domain}.")
                    continue
                    
                added = 0
                seen = set()
                for rec in passive_records:
                    host = rec.get('hostname', '').strip().lower()
                    record_type = rec.get('record_type', '')
                    ip = rec.get('address', '').strip() if record_type == 'A' else None
                    
                    if not is_valid_subdomain(host, domain) or host in seen:
                        continue
                    seen.add(host)
                    
                    if not ip:
                        ip = resolve_ip(host)
                    
                    geo = get_ip_geolocation(ip) if ip else None
                    country = geo.get('country') if geo else None
                    region = geo.get('region') if geo else None
                    lat = geo.get('latitude') if geo else None
                    lon = geo.get('longitude') if geo else None
                    notes = f"AlienVault OTX | {geo.get('notes') or ''}".strip(' |')
                    
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
                    
                self.output(f"Harvested {added} passive DNS host records for {domain} from AlienVault OTX.")
            except Exception as e:
                self.error(f"Error querying AlienVault OTX: {e}")

