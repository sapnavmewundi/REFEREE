/*
  REFEREE - YARA rules for identifying drivers with high-risk kernel import combinations
  Use: scan driver files on disk to flag those importing risky API combinations
  These are DETECTION rules for defenders to audit their driver inventory.
*/

rule HighRisk_KernelDriver_MemoryAccess
{
    meta:
        description = "Detects kernel drivers importing APIs for broad memory access"
        author = "REFEREE Project"
        severity = "high"
        reference = "https://loldrivers.io"

    strings:
        $mmap1 = "MmMapIoSpace" ascii
        $mmap2 = "ZwMapViewOfSection" ascii
        $mmap3 = "MmCopyMemory" ascii
        $mmap4 = "MmGetPhysicalAddress" ascii
        $mdl1  = "IoAllocateMdl" ascii
        $mdl2  = "MmBuildMdlForNonPagedPool" ascii
        $mz    = { 4D 5A }

    condition:
        $mz at 0 and (2 of ($mmap*) or ($mdl1 and $mdl2))
}

rule HighRisk_KernelDriver_ProcessManip
{
    meta:
        description = "Detects kernel drivers importing cross-process manipulation APIs"
        author = "REFEREE Project"
        severity = "high"

    strings:
        $p1 = "ZwOpenProcess" ascii
        $p2 = "PsLookupProcessByProcessId" ascii
        $p3 = "MmCopyVirtualMemory" ascii
        $p4 = "ZwTerminateProcess" ascii
        $p5 = "KeAttachProcess" ascii
        $mz = { 4D 5A }

    condition:
        $mz at 0 and 2 of ($p*)
}

rule HighRisk_KernelDriver_CallbackRemoval
{
    meta:
        description = "Detects kernel drivers importing APIs to remove defensive callbacks"
        author = "REFEREE Project"
        severity = "critical"

    strings:
        $c1 = "CmUnRegisterCallback" ascii
        $c2 = "ObUnRegisterCallbacks" ascii
        $c3 = "PsSetCreateProcessNotifyRoutine" ascii
        $c4 = "PsRemoveCreateThreadNotifyRoutine" ascii
        $c5 = "PsRemoveLoadImageNotifyRoutine" ascii
        $mz = { 4D 5A }

    condition:
        $mz at 0 and 2 of ($c*)
}

rule KnownAbuse_AntiCheat_mhyprot
{
    meta:
        description = "Detects mhyprot2/mhyprot3 anti-cheat driver with known abuse history"
        author = "REFEREE Project"
        severity = "critical"
        reference = "https://loldrivers.io"

    strings:
        $s1 = "mhyprot" ascii nocase
        $s2 = "miHoYo" ascii nocase
        $dev = "\\\\.\\mhyprot" ascii
        $mz = { 4D 5A }

    condition:
        $mz at 0 and ($dev or ($s1 and $s2))
}
