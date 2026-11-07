from recon.core.module import BaseModule

class Module(BaseModule):

    meta = {
        'name': 'Custom Subdomain Discovery Example',
        'author': 'Developer',
        'version': '1.0',
        'description': 'Example custom module that demonstrates how to query target domains and insert hosts into the database.',
        'comments': (
            'Demonstrates how to fetch target domains from the workspace database,',
            'perform external requests, and store results into the hosts table.',
        ),
        'query': 'SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL',
        'options': (
            ('timeout', 10, True, 'HTTP request timeout in seconds'),
        ),
    }

    def module_run(self, domains):
        for domain in domains:
            self.heading(domain, level=0)
            
            # Example: Construct sample subdomains or make an external API/HTTP request
            # resp = self.request('GET', f'https://api.example.com/subdomains?domain={domain}')
            # hosts = resp.json().get('subdomains', [])
            
            sample_subdomains = [f"www.{domain}", f"mail.{domain}", f"admin.{domain}"]
            
            for sub in sample_subdomains:
                self.output(f"Discovered sub: {sub}")
                # Store discovered host into the workspace SQLite database
                self.insert_hosts(host=sub, notes='Discovered by custom module')

