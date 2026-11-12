# REFEREE — Threat Model (stub)

## Assets
- EDR/AV telemetry integrity
- Process/memory isolation guarantees
- Trust placed in WHQL-signed anti-cheat drivers

## Attacker
- Local user (gamer-privilege) seeking kernel capability without BYOVD
- Goal: ring-0 R/W via an already-installed, whitelisted anti-cheat driver

## Trust assumptions exploited
- Signed driver == trusted by AV/EDR allowlists
- Anti-cheat IOCTL surface exposes broad R/W by design
- EDR self-protection assumes no trusted driver will be turned against it

## Capabilities to map (see docs/PRIMITIVES.md)
- Arbitrary kernel read / write
- Process handle / protection stripping
- ETW / callback teardown (telemetry blinding)

## Out of scope
- Shipping a generalized EDR-kill tool
- Undisclosed 0-day driver abuse presented before CVD completes
