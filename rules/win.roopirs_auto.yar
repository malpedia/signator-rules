rule win_roopirs_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.roopirs."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.roopirs"
        malpedia_rule_date = "20221118"
        malpedia_hash = "e0702e2e6d1d00da65c8a29a4ebacd0a4c59e1af"
        malpedia_version = "20221125"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 8b55dc 52 ff5128 dbe2 894580 837d8000 }
            // n = 6, score = 100
            //   8b55dc               | mov                 edx, dword ptr [ebp - 0x24]
            //   52                   | push                edx
            //   ff5128               | call                dword ptr [ecx + 0x28]
            //   dbe2                 | fnclex              
            //   894580               | mov                 dword ptr [ebp - 0x80], eax
            //   837d8000             | cmp                 dword ptr [ebp - 0x80], 0

        $sequence_1 = { 0fbf4db0 85c9 7433 c745fc32000000 8b55d8 52 68???????? }
            // n = 7, score = 100
            //   0fbf4db0             | movsx               ecx, word ptr [ebp - 0x50]
            //   85c9                 | test                ecx, ecx
            //   7433                 | je                  0x35
            //   c745fc32000000       | mov                 dword ptr [ebp - 4], 0x32
            //   8b55d8               | mov                 edx, dword ptr [ebp - 0x28]
            //   52                   | push                edx
            //   68????????           |                     

        $sequence_2 = { 50 ff516c dbe2 894580 837d8000 7d20 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   ff516c               | call                dword ptr [ecx + 0x6c]
            //   dbe2                 | fnclex              
            //   894580               | mov                 dword ptr [ebp - 0x80], eax
            //   837d8000             | cmp                 dword ptr [ebp - 0x80], 0
            //   7d20                 | jge                 0x22

        $sequence_3 = { 8b45dc 8b08 8b55dc 52 ff514c }
            // n = 5, score = 100
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8b55dc               | mov                 edx, dword ptr [ebp - 0x24]
            //   52                   | push                edx
            //   ff514c               | call                dword ptr [ecx + 0x4c]

        $sequence_4 = { 89410c 8bcc 8b45b8 6a02 8939 }
            // n = 5, score = 100
            //   89410c               | mov                 dword ptr [ecx + 0xc], eax
            //   8bcc                 | mov                 ecx, esp
            //   8b45b8               | mov                 eax, dword ptr [ebp - 0x48]
            //   6a02                 | push                2
            //   8939                 | mov                 dword ptr [ecx], edi

        $sequence_5 = { 51 ff5014 dbe2 89857cffffff 83bd7cffffff00 7d20 6a14 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   ff5014               | call                dword ptr [eax + 0x14]
            //   dbe2                 | fnclex              
            //   89857cffffff         | mov                 dword ptr [ebp - 0x84], eax
            //   83bd7cffffff00       | cmp                 dword ptr [ebp - 0x84], 0
            //   7d20                 | jge                 0x22
            //   6a14                 | push                0x14

        $sequence_6 = { c745c800000000 8b4d80 51 8d55a0 52 ff15???????? 50 }
            // n = 7, score = 100
            //   c745c800000000       | mov                 dword ptr [ebp - 0x38], 0
            //   8b4d80               | mov                 ecx, dword ptr [ebp - 0x80]
            //   51                   | push                ecx
            //   8d55a0               | lea                 edx, [ebp - 0x60]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   50                   | push                eax

        $sequence_7 = { 56 57 8965e8 c745ec00114000 c745f000000000 c745f400000000 c745fc01000000 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   8965e8               | mov                 dword ptr [ebp - 0x18], esp
            //   c745ec00114000       | mov                 dword ptr [ebp - 0x14], 0x401100
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1

        $sequence_8 = { ff15???????? c745fc06000000 8d45c8 50 8b4dd8 51 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   c745fc06000000       | mov                 dword ptr [ebp - 4], 6
            //   8d45c8               | lea                 eax, [ebp - 0x38]
            //   50                   | push                eax
            //   8b4dd8               | mov                 ecx, dword ptr [ebp - 0x28]
            //   51                   | push                ecx

        $sequence_9 = { 68???????? 8b4ddc 51 8b55bc 52 ff15???????? 898568ffffff }
            // n = 7, score = 100
            //   68????????           |                     
            //   8b4ddc               | mov                 ecx, dword ptr [ebp - 0x24]
            //   51                   | push                ecx
            //   8b55bc               | mov                 edx, dword ptr [ebp - 0x44]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   898568ffffff         | mov                 dword ptr [ebp - 0x98], eax

    condition:
        7 of them and filesize < 344064
}