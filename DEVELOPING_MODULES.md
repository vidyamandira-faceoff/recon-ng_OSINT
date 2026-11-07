# Authoring Custom Recon-ng Modules

Recon-ng allows you to write custom reconnaissance modules that integrate directly into the CLI, automated `.rc` scripts, and the Web Dashboard.

---

## 1. Where Custom Modules Live

Recon-ng dynamically discovers all `.py` files inside your user profile directory:
```text
C:\Users\<username>\.recon-ng\modules\<category>\<subcategory>\<module_name>.py
```

For example, to create a custom host discovery module:
```text
C:\Users\<username>\.recon-ng\modules\recon\domains-hosts\my_scanner.py
```
Recon-ng will automatically detect and load it as:
`recon/domains-hosts/my_scanner`

---

## 2. Basic Module Anatomy

Every module inherits from `BaseModule`:

```python
from recon.core.module import BaseModule

class Module(BaseModule):

    meta = {
        'name': 'Module Display Name',
        'author': 'Your Name (@handle)',
        'version': '1.0',
        'description': 'Description of what this module investigates.',
        # SQL query that fetches input targets from the active workspace
        'query': 'SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL',
        # Configurable module parameters (name, default, required, description)
        'options': (
            ('timeout', 10, True, 'HTTP request timeout in seconds'),
        ),
        # Optional: API keys required to run
        'required_keys': ['my_custom_api_key'],
    }

    def module_run(self, domains):
        for domain in domains:
            self.heading(domain, level=0)
            
            # 1. Use the framework's HTTP request helper
            # resp = self.request('GET', f'https://api.example.com/lookup?d={domain}')
            
            # 2. Log messages to the terminal / web console
            self.output(f"Found host for {domain}")
            
            # 3. Store results in the workspace database
            self.insert_hosts(host=f"portal.{domain}", ip_address="192.0.2.1", notes="Custom scan")
```

---

## 3. Database Insertion Methods

Recon-ng provides built-in helper methods that sanitize and insert records into the database:

| Helper Method | Description |
| :--- | :--- |
| `self.insert_domains(domain=...)` | Add target domain |
| `self.insert_hosts(host=..., ip_address=..., country=...)` | Add host / subdomain |
| `self.insert_companies(company=..., description=...)` | Add company / organization |
| `self.insert_contacts(first_name=..., last_name=..., email=...)` | Add person / employee |
| `self.insert_credentials(username=..., password=..., _hash=...)` | Add leaked credential |
| `self.insert_ports(ip_address=..., host=..., port=..., protocol=...)` | Add open network port |
| `self.insert_vulnerabilities(host=..., reference=..., category=...)` | Add vulnerability finding |

---

## 4. Testing Your Custom Module

1. Copy your `.py` file into `~/.recon-ng/modules/<category>/<subcategory>/`.
2. Reload modules in the terminal:
   ```text
   [recon-ng][default] > modules reload
   ```
3. Load and test your module:
   ```text
   [recon-ng][default] > modules load recon/domains-hosts/my_scanner
   [recon-ng][default][my_scanner] > run
   ```
4. Or open the Web Dashboard at **`http://127.0.0.1:5000`** ➔ **`⚡ Modules & Run`** and your custom module will appear in the search list automatically!

