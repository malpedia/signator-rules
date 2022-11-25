rule win_webc2_bolid_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.webc2_bolid."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_bolid"
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
        $sequence_0 = { 68???????? 64a100000000 50 64892500000000 83ec10 8a45f3 }
            // n = 6, score = 100
            //   68????????           |                     
            //   64a100000000         | mov                 eax, dword ptr fs:[0]
            //   50                   | push                eax
            //   64892500000000       | mov                 dword ptr fs:[0], esp
            //   83ec10               | sub                 esp, 0x10
            //   8a45f3               | mov                 al, byte ptr [ebp - 0xd]

        $sequence_1 = { 83c40c 2bc6 8bcf 6a00 50 894508 e8???????? }
            // n = 7, score = 100
            //   83c40c               | add                 esp, 0xc
            //   2bc6                 | sub                 eax, esi
            //   8bcf                 | mov                 ecx, edi
            //   6a00                 | push                0
            //   50                   | push                eax
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   e8????????           |                     

        $sequence_2 = { f2ae f7d1 49 8bf1 8d8bdc000000 56 8975e8 }
            // n = 7, score = 100
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx
            //   8bf1                 | mov                 esi, ecx
            //   8d8bdc000000         | lea                 ecx, [ebx + 0xdc]
            //   56                   | push                esi
            //   8975e8               | mov                 dword ptr [ebp - 0x18], esi

        $sequence_3 = { 83c314 f2ae f7d1 49 6a01 8be9 }
            // n = 6, score = 100
            //   83c314               | add                 ebx, 0x14
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx
            //   6a01                 | push                1
            //   8be9                 | mov                 ebp, ecx

        $sequence_4 = { 7509 ff15???????? 89432c 8b8394000000 }
            // n = 4, score = 100
            //   7509                 | jne                 0xb
            //   ff15????????         |                     
            //   89432c               | mov                 dword ptr [ebx + 0x2c], eax
            //   8b8394000000         | mov                 eax, dword ptr [ebx + 0x94]

        $sequence_5 = { 895c242c 895c2430 6a01 895c2438 c68424000200000a }
            // n = 5, score = 100
            //   895c242c             | mov                 dword ptr [esp + 0x2c], ebx
            //   895c2430             | mov                 dword ptr [esp + 0x30], ebx
            //   6a01                 | push                1
            //   895c2438             | mov                 dword ptr [esp + 0x38], ebx
            //   c68424000200000a     | mov                 byte ptr [esp + 0x200], 0xa

        $sequence_6 = { 8d442424 52 53 50 8bce e8???????? 8bcd }
            // n = 7, score = 100
            //   8d442424             | lea                 eax, [esp + 0x24]
            //   52                   | push                edx
            //   53                   | push                ebx
            //   50                   | push                eax
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   8bcd                 | mov                 ecx, ebp

        $sequence_7 = { 8a4c2413 53 884c2460 8d4c2460 c684240002000001 e8???????? 8a542413 }
            // n = 7, score = 100
            //   8a4c2413             | mov                 cl, byte ptr [esp + 0x13]
            //   53                   | push                ebx
            //   884c2460             | mov                 byte ptr [esp + 0x60], cl
            //   8d4c2460             | lea                 ecx, [esp + 0x60]
            //   c684240002000001     | mov                 byte ptr [esp + 0x200], 1
            //   e8????????           |                     
            //   8a542413             | mov                 dl, byte ptr [esp + 0x13]

        $sequence_8 = { 897598 f7d1 49 51 68???????? 50 56 }
            // n = 7, score = 100
            //   897598               | mov                 dword ptr [ebp - 0x68], esi
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx
            //   51                   | push                ecx
            //   68????????           |                     
            //   50                   | push                eax
            //   56                   | push                esi

        $sequence_9 = { c745e801000000 ffd7 8bf0 85f6 0f8e08010000 }
            // n = 5, score = 100
            //   c745e801000000       | mov                 dword ptr [ebp - 0x18], 1
            //   ffd7                 | call                edi
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   0f8e08010000         | jle                 0x10e

    condition:
        7 of them and filesize < 163840
}