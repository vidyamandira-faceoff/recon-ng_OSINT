"""
---
name: Hostname DNS Resolver
description: Resolves harvested hostnames to IP addresses using system DNS resolvers.
author: Recon-ng Team
version: '1.0'
query: SELECT DISTINCT host FROM hosts WHERE host IS NOT NULL AND ip_address IS NULL
---
"""
import socket
from recon.core.module import BaseModule


class Module(BaseModule):

    def module_run(self, hosts):
        self.heading(f"Resolving {len(hosts)} hostnames", level=0)
        resolved = 0
        for host in hosts:
            try:
                ip = socket.gethostbyname(host)
                self.output(f"{host} => {ip}")
                self.query('UPDATE hosts SET ip_address = ? WHERE host = ?', (ip, host))
                resolved += 1
            except (socket.gaierror, socket.error):
                self.debug(f"Unable to resolve {host}")
            except Exception as e:
                self.error(f"DNS resolution error for {host}: {e}")
        self.output(f"Successfully resolved {resolved} / {len(hosts)} hosts.")

