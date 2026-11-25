# CISA Cybersecurity Advisory: Business Email Compromise (BEC) & Vendor Fraud

## Attack Pattern Summary
Business Email Compromise (BEC) attacks exploit human trust rather than technical malware payloads. Threat actors impersonate CEOs, CFOs, legal counsel, or established suppliers to authorize fraudulent wire transfers or divert payroll/vendor payments.

## Primary Behavioral & Technical Indicators
1. **Artificial Urgency & Secrecy:** Phrases such as "confidential acquisition," "tied up in a board meeting," "cannot take phone calls," or "must be completed before COB/end of day."
2. **Lookalike / Homoglyph Domains:** Registering domains visually similar to the victim organization (e.g., replacing `o` with `0`, `l` with `1`, or adding `-corp`/`-security` suffixes).
3. **Reply-To Header Divergence:** The `From` header displays an executive's name, while the `Reply-To` header routes responses to a free webmail account (`@gmail.com`, `@outlook.com`) or an attacker-controlled external domain.
4. **Supplier Bank Account Change Requests:** Requests to update beneficiary banking instructions, routing numbers, or escrow accounts without prior multi-factor out-of-band verification.

## Incident Response & Containment Guidance
- Quarantine suspicious messages pending Security Operations Center (SOC) analyst review.
- Never reply directly to the suspicious email thread to verify authenticity.
- Require independent phone verification using a pre-existing, known-good phone number from the internal corporate directory.