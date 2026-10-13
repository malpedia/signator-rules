import "pe"

rule Win_Research_Framework_Hopeless {
    meta:
        author        = "zdn2pwn"
        description   = "Comprehensive codebase detection for Hopeless hybrid research framework (Bootkit + Wiper + Ransomware)"
        reference     = "https://github.com/zdn2pwn/Hopeless"
        reference2    = "https://github.com/muhammadzidane632/Hopeless (suspended)"
        date          = "2026-07-24"
        version       = "2.1"
        malpedia_family = "win.hopeless"
        scope         = "Research and Education Only"
        uniqueness    = "High"

    strings:
        // ==========================================
        // 1. Command-line Parameters (Argv Processing)
        // ==========================================
        $param_clean      = "-Clean"      ascii wide fullword
        $param_dryrun     = "-DryRun"     ascii wide fullword
        $param_aggressive = "-Aggressive" ascii wide fullword
        $param_force      = "-Force"      ascii wide fullword
        $param_disknum    = "-DiskNum"    ascii wide fullword

        // ==========================================
        // 2. Internal Versioning & Logging Strings
        // ==========================================
        $ver_v4   = "v4: Semi-Aggressive Execution" ascii wide
        $ver_v5   = "v5: Non-Aggressive Execution" ascii wide
        $ver_mod  = "hopeless: Moderate Execution" ascii wide
        $ver_prv  = "xhopeless: Aggressive Execution" ascii wide
        $project  = "Recovery Hopeless" ascii wide

        // ==========================================
        // 3. Registry Targets
        // ==========================================
        $reg_ifeo     = "Image File Execution Options" ascii wide
        $reg_safeboot = "SafeBoot" ascii wide
        $reg_sam      = "\\SAM"      ascii wide nocase
        $reg_security = "\\SECURITY" ascii wide nocase
        $reg_software = "\\SOFTWARE" ascii wide nocase
        $reg_system   = "\\SYSTEM"   ascii wide nocase

        // ==========================================
        // 4. Low-level Disk & Firmware Access
        // ==========================================
        $disk_physical = "\\\\.\\PhysicalDrive" ascii wide
        $firm_nvram    = "SYSTEM\\CurrentControlSet\\Control\\SecureBoot" ascii wide nocase

        // ==========================================
        // 5. Critical System API (Phase 10)
        // ==========================================
        $api_harderror = "NtRaiseHardError" ascii wide fullword

    condition:
        // Pastikan file adalah Windows PE Executable
        uint16(0) == 0x5A4D and pe.is_pe and

        (
            // Scenario A: Minimal 3 parameter unik
            3 of ($param_*) or

            // Scenario B: String versioning / logging internal
            2 of ($ver_*) or
            $project or

            // Scenario C: Kombinasi destruktif (Raw Disk Write + Hard BSOD)
            ($disk_physical and $api_harderror) or

            // Scenario D: Registry manipulation masif (IFEO + SafeBoot)
            ($reg_ifeo and $reg_safeboot and 2 of ($reg_s*))
        )
}