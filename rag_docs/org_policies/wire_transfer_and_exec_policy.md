# AcmeCorp Internal Financial & Email Security Policy (Policy ID: SEC-FIN-2026)

## Official Corporate Domain
- AcmeCorp's sole authorized corporate email domain is `acmecorp.com`.
- Any email claiming to originate from an AcmeCorp executive or employee using lookalike domains (such as `acmec0rp.com`, `acme-corp.com`, or personal webmail accounts) must be treated as a suspected impersonation attempt.

## Wire Transfer & Vendor Banking Change Rules
1. **Dual Out-of-Band Authorization:** All wire transfers exceeding $10,000 USD or any request to modify supplier beneficiary bank details require verbal confirmation via an internally registered phone number before execution.
2. **No Email-Only Executive Overrides:** Executives (including the CEO and CFO) are prohibited from bypassing standard Accounts Payable approval workflows via urgent or confidential email requests.
3. **Authentication Enforcement:** External emails claiming to represent AcmeCorp leadership that fail SPF, DKIM, or DMARC alignment must be immediately quarantined for SOC analyst triage.