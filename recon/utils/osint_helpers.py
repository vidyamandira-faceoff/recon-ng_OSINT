"""
Recon-ng OSINT Helper Utilities
Provides fast, cached IP resolution, Geolocation, RDAP/WHOIS parsing, and subdomain filtering.
"""
import re
import socket
import urllib.request
import json
import logging

_GEO_CACHE = {}
_RESOLVE_CACHE = {}


def is_valid_subdomain(host, domain):
    """
    Checks if a host string is a genuine, valid subdomain of the target domain.
    """
    if not host or not isinstance(host, str):
        return False
    host = host.strip().lower()
    # Reject wildcards, spaces, slashes, or emails
    if '*' in host or '/' in host or ' ' in host or '@' in host:
        return False
    domain = domain.strip().lower()
    if not (host == domain or host.endswith('.' + domain)):
        return False
    # Reject empty or invalid parts
    parts = host.split('.')
    if any(len(p) == 0 for p in parts):
        return False
    return True


def resolve_ip(host, timeout=1.5):
    """
    Resolves hostname to IPv4 address with local caching.
    """
    if not host:
        return None
    host = host.strip().lower()
    if host in _RESOLVE_CACHE:
        return _RESOLVE_CACHE[host]
    
    # Check if host is already an IP address
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


def get_ip_geolocation(ip_address, timeout=2.0):
    """
    Fetches real geographic details (country, region, city, lat, lon, ISP)
    from ip-api.com with local in-memory caching.
    """
    if not ip_address:
        return None
    ip_address = ip_address.strip()
    if ip_address in _GEO_CACHE:
        return _GEO_CACHE[ip_address]
    
    # Skip private / loopback IP addresses
    if ip_address.startswith(('127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')):
        res = {
            'country': 'Private Network',
            'region': 'Local',
            'latitude': None,
            'longitude': None,
            'notes': 'RFC 1918 Private IP'
        }
        _GEO_CACHE[ip_address] = res
        return res

    url = f"http://ip-api.com/json/{ip_address}?fields=status,country,regionName,city,lat,lon,isp,org,as"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (compatible; Recon-ng/5.1)'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get('status') == 'success':
                city = data.get('city') or ''
                region_name = data.get('regionName') or ''
                region_str = f"{region_name}, {city}".strip(', ') if region_name or city else None
                org_info = data.get('org') or data.get('isp') or data.get('as') or ''
                res = {
                    'country': data.get('country'),
                    'region': region_str,
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon'),
                    'notes': org_info[:100] if org_info else None
                }
                _GEO_CACHE[ip_address] = res
                return res
    except Exception:
        pass

    _GEO_CACHE[ip_address] = None
    return None
