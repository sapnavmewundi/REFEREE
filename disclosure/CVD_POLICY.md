# REFEREE - Coordinated Vulnerability Disclosure Policy

## Commitment
The REFEREE project follows coordinated vulnerability disclosure (CVD) per
ISO/IEC 29147:2018. We notify affected vendors before any public presentation
or tool release that names a specific, previously-unreported vulnerability.

## Timeline
1. **T+0** - Initial vendor notification via their published security contact
   (security@vendor or bug-bounty program).
2. **T+14 days** - Follow-up if no acknowledgment received.
3. **T+90 days** - Public disclosure window opens. If the vendor has engaged
   and a fix is in progress, we extend by mutual agreement.
4. **Presentation date** - Must be >= T+90 unless the vendor grants earlier
   clearance in writing.

## What we disclose
- The class of risk (e.g., "driver exposes broad kernel access to user-mode callers").
- Enough detail for the vendor to reproduce and remediate.
- We do NOT release working code targeting specific shipping drivers before
  the disclosure window closes.

## What we release publicly
- The REFEREE **auditor** and **capability scanner** (identifies risk signals
  in drivers already installed on a host; does not send IOCTLs or interact
  with driver interfaces).
- **Detection rules** (Sigma/YARA) for defenders to monitor for abuse patterns.
- **Aggregate statistics** (e.g., "X of Y drivers scored CRITICAL") without
  naming specific undisclosed vulnerabilities.

## Vendor contacts log

| Vendor | Product | Contact | Date notified | Ack? | Status |
|--------|---------|---------|---------------|------|--------|
| (TBD)  | (TBD)   | (TBD)  | (TBD)         | -    | Pending research |

## Safe harbor
This research is conducted in good faith for defensive purposes. We do not
access systems we do not own. All testing is performed on our own hardware
with drivers we installed ourselves or in isolated lab environments.

## Contact
To report a concern about this research: chowdaryprajwal2@gmail.com
