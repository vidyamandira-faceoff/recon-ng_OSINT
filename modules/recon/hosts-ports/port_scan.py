"""
---
name: Live Port Scanner & Service Banner Grabber
description: Scans common live ports (80, 443, 8080, 8443, 22, 21, 25, 53) on discovered hosts and captures service banners (HTTP Server headers, SSH versions).
author: Recon-ng Team
version: '1.2'
query: SELECT DISTINCT host, ip_address FROM hosts WHERE host IS NOT NULL
---
"""
import socket
import ssl
from recon.core.module import BaseModule

TARGET_PORTS = [
    (80, 'http'),
    (443, 'https'),
    (8080, 'http-alt'),
    (8443, 'https-alt'),
    (22, 'ssh'),
    (21, 'ftp'),
    (25, 'smtp')
]


def probe_port(target_host, target_ip, port, service, timeout=1.5):
    target = target_ip or target_host
    banner = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        
        if service in ['http', 'http-alt']:
            req = f"HEAD / HTTP/1.1\r\nHost: {target_host}\r\nUser-Agent: Recon-ng/5.1\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode('utf-8'))
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
                    req = f"HEAD / HTTP/1.1\r\nHost: {target_host}\r\nUser-Agent: Recon-ng/5.1\r\nConnection: close\r\n\r\n"
                    ss.sendall(req.encode('utf-8'))
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


class Module(BaseModule):

    def module_run(self, host_tuples):
        targets = []
        for item in host_tuples[:10]:
            if isinstance(item, (list, tuple)):
                h = item[0]
                ip = item[1] if len(item) > 1 and item[1] else h
            else:
                h = str(item)
                ip = h
            targets.append((h, ip))

        if not targets:
            doms = self.query('SELECT DISTINCT domain FROM domains')
            for d in doms:
                dom = d[0]
                targets.append((dom, dom))
                targets.append((f"www.{dom}", f"www.{dom}"))

        self.heading(f"Scanning common ports on {len(targets)} targets", level=0)
        total_open = 0
        for host, ip in targets:
            for port, service in TARGET_PORTS:
                res = probe_port(host, ip, port, service)
                if res:
                    port, service, banner = res
                    self.insert_ports(
                        ip_address=ip if ip != host else None,
                        host=host,
                        port=port,
                        protocol='tcp',
                        banner=banner,
                        notes=service
                    )
                    self.output(f" [OPEN PORT] {host}:{port}/tcp ({service}) -> {banner}")
                    total_open += 1
                        
        self.output(f"Port scan completed. Discovered {total_open} live service ports.")
