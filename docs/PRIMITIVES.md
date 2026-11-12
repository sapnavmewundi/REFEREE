# REFEREE — Kernel Driver Risk Taxonomy

## Purpose
This taxonomy helps **defenders** identify which kernel drivers on a fleet
pose elevated risk due to the capabilities they expose. It is modeled on the
LOLDrivers (loldrivers.io) approach: catalog what a driver *can* do, so
blue teams can prioritize monitoring and blocklisting.

## Risk categories (scored by the REFEREE capability scanner)

### Category A — Broad memory access
Drivers that import APIs associated with mapping or accessing physical or
virtual memory regions beyond their own address space.
- **Detection signal:** PE imports of MmMapIoSpace, ZwMapViewOfSection,
  MmCopyMemory, MmGetPhysicalAddress, or IoAllocateMdl with MmBuildMdlForNonPagedPool.
- **Why it matters:** A driver with these imports *may* expose an IOCTL that
  lets a user-mode caller read or write kernel memory. This is the primitive
  most commonly abused in BYOVD and anti-cheat weaponization attacks.

### Category B — Process/thread manipulation
Drivers that import APIs to open, modify, or terminate other processes
from kernel mode.
- **Detection signal:** ZwOpenProcess, PsLookupProcessByProcessId,
  ObOpenObjectByPointer, MmCopyVirtualMemory, ZwTerminateProcess.
- **Why it matters:** Enables cross-process memory access or process
  termination from kernel context, bypassing user-mode protections.

### Category C — Registry/callback manipulation
Drivers that import APIs to register or remove kernel callbacks, or
modify protected registry keys.
- **Detection signal:** CmUnRegisterCallback, ObUnRegisterCallbacks,
  PsSetCreateProcessNotifyRoutine (with Remove=TRUE).
- **Why it matters:** Removing defensive callbacks is how telemetry
  (ETW, minifilter, process-creation notifications) gets blinded.

### Category D — Permissive device ACLs
Drivers whose device object is accessible from medium-integrity or
lower-privilege processes.
- **Detection signal:** Device object DACL allows GENERIC_READ/WRITE
  to Everyone, Users, or medium-integrity SIDs.
- **Why it matters:** Even a powerful driver is low-risk if only SYSTEM
  can talk to it. Permissive ACLs are the reachability gate.

## Scoring
Each driver gets a composite score:
- +25 per category (A–D) where imports or ACLs match
- +15 if the driver is currently loaded and running
- +10 if the signer is valid (counterintuitively: valid = AV-trusted = more abusable)
- +10 if the driver appears in loldrivers.io or has public abuse history
- Max 100. Thresholds: ≥70 CRITICAL, ≥45 HIGH, ≥25 MEDIUM, <25 LOW.

## References
- loldrivers.io — Living Off The Land Drivers catalog
- Microsoft recommended driver block rules
- MSRC guidance on vulnerable driver blocklisting
