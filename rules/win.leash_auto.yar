rule win_leash_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.leash."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.leash"
        malpedia_rule_date = "20220513"
        malpedia_hash = "7f4b2229e6ae614d86d74917f6d5b41890e62a26"
        malpedia_version = "20220516"
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
        $sequence_0 = { 8b7de4 83c9ff f2ae f7d1 2bf9 8bf7 8bd9 }
            // n = 7, score = 200
            //   8b7de4               | mov                 edi, dword ptr [ebp - 0x1c]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   2bf9                 | sub                 edi, ecx
            //   8bf7                 | mov                 esi, edi
            //   8bd9                 | mov                 ebx, ecx

        $sequence_1 = { 83c414 8d4ddc e8???????? 8b45e0 8b4d08 8d95a0feffff 52 }
            // n = 7, score = 200
            //   83c414               | add                 esp, 0x14
            //   8d4ddc               | lea                 ecx, [ebp - 0x24]
            //   e8????????           |                     
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8d95a0feffff         | lea                 edx, [ebp - 0x160]
            //   52                   | push                edx

        $sequence_2 = { 6a10 68???????? eb35 83fa06 7510 8d8d5cf9ffff }
            // n = 6, score = 200
            //   6a10                 | push                0x10
            //   68????????           |                     
            //   eb35                 | jmp                 0x37
            //   83fa06               | cmp                 edx, 6
            //   7510                 | jne                 0x12
            //   8d8d5cf9ffff         | lea                 ecx, [ebp - 0x6a4]

        $sequence_3 = { 8bf0 51 6a10 68???????? 89742438 }
            // n = 5, score = 200
            //   8bf0                 | mov                 esi, eax
            //   51                   | push                ecx
            //   6a10                 | push                0x10
            //   68????????           |                     
            //   89742438             | mov                 dword ptr [esp + 0x38], esi

        $sequence_4 = { 8d4de8 c645fc01 e8???????? 8d4dec c645fc00 e8???????? 8b4df4 }
            // n = 7, score = 200
            //   8d4de8               | lea                 ecx, [ebp - 0x18]
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   e8????????           |                     
            //   8d4dec               | lea                 ecx, [ebp - 0x14]
            //   c645fc00             | mov                 byte ptr [ebp - 4], 0
            //   e8????????           |                     
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_5 = { 50 e8???????? 83c408 85c0 7411 8bb608040000 }
            // n = 6, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   7411                 | je                  0x13
            //   8bb608040000         | mov                 esi, dword ptr [esi + 0x408]

        $sequence_6 = { dc0d???????? 43 dd55dc ebe7 ddd8 dc0d???????? 83ec08 }
            // n = 7, score = 200
            //   dc0d????????         |                     
            //   43                   | inc                 ebx
            //   dd55dc               | fst                 qword ptr [ebp - 0x24]
            //   ebe7                 | jmp                 0xffffffe9
            //   ddd8                 | fstp                st(0)
            //   dc0d????????         |                     
            //   83ec08               | sub                 esp, 8

        $sequence_7 = { 50 8bcf ff5234 8b5d10 8bf0 85f6 0f86e7000000 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   8bcf                 | mov                 ecx, edi
            //   ff5234               | call                dword ptr [edx + 0x34]
            //   8b5d10               | mov                 ebx, dword ptr [ebp + 0x10]
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   0f86e7000000         | jbe                 0xed

        $sequence_8 = { f2ae f7d1 2bf9 8d55d0 8bc1 }
            // n = 5, score = 200
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   2bf9                 | sub                 edi, ecx
            //   8d55d0               | lea                 edx, [ebp - 0x30]
            //   8bc1                 | mov                 eax, ecx

        $sequence_9 = { e9???????? 8d8424fc290000 8d8c24fc050000 50 51 e8???????? }
            // n = 6, score = 200
            //   e9????????           |                     
            //   8d8424fc290000       | lea                 eax, [esp + 0x29fc]
            //   8d8c24fc050000       | lea                 ecx, [esp + 0x5fc]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   e8????????           |                     

    condition:
        7 of them and filesize < 761856
}