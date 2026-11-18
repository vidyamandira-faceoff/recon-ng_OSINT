"""
---
name: Host IP Geolocation Enricher
description: Looks up real-world country, region, latitude, longitude, and ISP data for hosts in the database.
author: Recon-ng Team
version: '1.0'
query: SELECT DISTINCT host, ip_address FROM hosts WHERE host IS NOT NULL
---
"""
from recon.core.module import BaseModule
from recon.utils.osint_helpers import resolve_ip, get_ip_geolocation


class Module(BaseModule):

    def module_run(self, host_tuples):
        self.heading(f"Enriching geolocation for {len(host_tuples)} hosts", level=0)
        enriched = 0
        for item in host_tuples:
            host = item[0]
            ip = item[1] if len(item) > 1 and item[1] else None
            if not ip:
                ip = resolve_ip(host)
            if not ip:
                continue

            geo = get_ip_geolocation(ip)
            if geo and geo.get('country'):
                country = geo.get('country')
                region = geo.get('region')
                lat = geo.get('latitude')
                lon = geo.get('longitude')
                notes = geo.get('notes')

                self.query(
                    'UPDATE hosts SET ip_address = ?, region = ?, country = ?, latitude = ?, longitude = ?, notes = ? WHERE host = ?',
                    (ip, region, country, lat, lon, notes, host)
                )
                if lat and lon:
                    self.insert_locations(latitude=lat, longitude=lon, street_address=f"{region or ''}, {country or ''}".strip(', '))
                self.output(f" -> {host} ({ip}) => {region}, {country} (Lat: {lat}, Lon: {lon})")
                enriched += 1

        self.output(f"Successfully enriched {enriched} hosts with geographic location data.")

