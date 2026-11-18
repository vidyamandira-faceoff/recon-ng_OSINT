"""
---
name: Whois & RDAP Contact Harvester
description: Harvests authentic registrant, administrative, and technical point-of-contact details, emails, and registrar data from RDAP and WHOIS registries.
author: Recon-ng Team
version: '1.3'
query: SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL
---
"""
import re
from recon.core.module import BaseModule


class Module(BaseModule):

    def module_run(self, domains):
        for domain in domains:
            self.heading(f"Harvesting WHOIS & Contact intelligence for {domain}", level=0)
            contacts_found = 0
            
            # Method 1: HackerTarget WHOIS API (Fast, Reliable, Standard Text)
            try:
                ht_url = 'https://api.hackertarget.com/whois/'
                resp = self.request('GET', ht_url, params={'q': domain})
                if resp.status_code == 200 and resp.text.strip():
                    text = resp.text
                    
                    # Extract registrar
                    reg_match = re.search(r'Registrar:\s*([^\r\n]+)', text, re.IGNORECASE)
                    registrar = reg_match.group(1).strip() if reg_match else None
                    if registrar:
                        self.insert_companies(company=registrar, description=f"Domain Registrar for {domain}")
                        
                    # Extract dates
                    created_match = re.search(r'Creation Date:\s*([^\r\n]+)', text, re.IGNORECASE)
                    created = created_match.group(1).strip()[:10] if created_match else None
                    
                    # Extract emails
                    emails = set(re.findall(r'[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}', text))
                    
                    # Extract phone
                    phone_match = re.search(r'(?:Phone|Tel):\s*([^\r\n]+)', text, re.IGNORECASE)
                    phone = phone_match.group(1).strip() if phone_match else None
                    
                    # Update domain notes
                    if registrar:
                        self.query('UPDATE domains SET notes = ? WHERE domain = ?', (f"Registrar: {registrar} | Created: {created or 'N/A'}", domain))
                    
                    for email in emails:
                        # Skip dummy or example emails
                        if any(x in email.lower() for x in ['example.com', 'schema.org', 'w3.org']):
                            continue
                        self.insert_contacts(
                            first_name=registrar or f"{domain.capitalize()} Admin",
                            email=email,
                            title='Registrar / Abuse Contact' if 'abuse' in email.lower() else 'Technical Contact',
                            phone=phone,
                            notes=f"WHOIS record for {domain}"
                        )
                        contacts_found += 1
                        self.output(f"[CONTACT] {email} (Phone: {phone or 'N/A'})")
            except Exception as e:
                self.debug(f"HackerTarget WHOIS fallback: {e}")

            # Method 2: RDAP Registry API
            if contacts_found == 0:
                try:
                    rdap_url = f"https://rdap.org/domain/{domain}"
                    resp = self.request('GET', rdap_url)
                    if resp.status_code == 200:
                        data = resp.json()
                        entities = data.get('entities', [])
                        for entity in entities:
                            roles = entity.get('roles', [])
                            role_str = ', '.join(roles).title() or 'Registrant'
                            vcard = entity.get('vcardArray', [])
                            fn = None
                            email = None
                            phone = None
                            if len(vcard) > 1 and isinstance(vcard[1], list):
                                for prop in vcard[1]:
                                    tag = prop[0] if len(prop) > 0 else ''
                                    val = prop[3] if len(prop) > 3 else None
                                    if tag == 'fn': fn = str(val).strip()
                                    elif tag == 'email': email = str(val).strip().lower()
                                    elif tag == 'tel': phone = str(val).strip()
                            if email or fn:
                                self.insert_contacts(
                                    first_name=fn or f"{role_str} Contact",
                                    email=email,
                                    title=role_str,
                                    phone=phone,
                                    notes=f"RDAP entity for {domain}"
                                )
                                contacts_found += 1
                                self.output(f"[CONTACT] {fn or role_str} | {email or 'N/A'}")
                except Exception as e:
                    self.debug(f"RDAP error: {e}")

            self.output(f"Harvested {contacts_found} authentic contacts for {domain}.")
