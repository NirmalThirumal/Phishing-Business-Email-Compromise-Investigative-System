# MITRE ATT&CK Technique T1566: Phishing (Initial Access)

## Overview
Adversaries send deceptive messages to gain access to victim systems or manipulate users into performing unauthorized actions. All forms of phishing are electronically delivered social engineering.

## Sub-Techniques & Indicators
- **T1566.001 Spearphishing Attachment:** Adversaries send malicious files (e.g., macro-enabled Office documents `.docm`/`.xlsm`, ISO/ZIP archives, or executables) disguised as invoices, remittance advice, or legal contracts.
- **T1566.002 Spearphishing Link:** Adversaries embed links to credential-harvesting portals or malicious payloads. Common indicators include raw IP-address URLs, URL shorteners, newly registered domains, and HTML anchor text displaying a trusted domain (e.g., `login.microsoftonline.com`) while pointing to an unrelated external host.
- **T1566.003 Spearphishing via Service & Display Name Spoofing:** Attackers forge sender display names to include trusted brand names or executive email addresses while sending from lookalike domains (typosquatting or homoglyph substitution).

## Recommended Mitigations
- **M1017 User Training:** Train finance and executive staff to verify out-of-band before acting on urgent credential or payment requests.
- **M1054 Software Configuration:** Enforce strict SPF, DKIM, and DMARC (`p=reject` or `p=quarantine`) email authentication policies.