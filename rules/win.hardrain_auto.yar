rule win_hardrain_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.hardrain."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hardrain"
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
        $sequence_0 = { 7564 8b4c2410 6a01 8d542428 51 52 }
            // n = 6, score = 200
            //   7564                 | jne                 0x66
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   6a01                 | push                1
            //   8d542428             | lea                 edx, [esp + 0x28]
            //   51                   | push                ecx
            //   52                   | push                edx

        $sequence_1 = { 668b4602 83c602 50 ff15???????? 8b4d00 }
            // n = 5, score = 200
            //   668b4602             | mov                 ax, word ptr [esi + 2]
            //   83c602               | add                 esi, 2
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b4d00               | mov                 ecx, dword ptr [ebp]

        $sequence_2 = { 55 56 85c0 7463 }
            // n = 4, score = 200
            //   55                   | push                ebp
            //   56                   | push                esi
            //   85c0                 | test                eax, eax
            //   7463                 | je                  0x65

        $sequence_3 = { 50 56 e8???????? 83c414 85c0 7407 b802000000 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   b802000000           | mov                 eax, 2

        $sequence_4 = { e8???????? 83c404 50 8d442440 50 e8???????? b90b000000 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   50                   | push                eax
            //   8d442440             | lea                 eax, [esp + 0x40]
            //   50                   | push                eax
            //   e8????????           |                     
            //   b90b000000           | mov                 ecx, 0xb

        $sequence_5 = { 52 e8???????? 33c0 b910000000 89442448 }
            // n = 5, score = 200
            //   52                   | push                edx
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   b910000000           | mov                 ecx, 0x10
            //   89442448             | mov                 dword ptr [esp + 0x48], eax

        $sequence_6 = { 81e7ffff0000 81e6ffff0000 8bd7 6a00 }
            // n = 4, score = 200
            //   81e7ffff0000         | and                 edi, 0xffff
            //   81e6ffff0000         | and                 esi, 0xffff
            //   8bd7                 | mov                 edx, edi
            //   6a00                 | push                0

        $sequence_7 = { 895c242c c744243000000000 ff15???????? 85c0 7eca }
            // n = 5, score = 200
            //   895c242c             | mov                 dword ptr [esp + 0x2c], ebx
            //   c744243000000000     | mov                 dword ptr [esp + 0x30], 0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7eca                 | jle                 0xffffffcc

        $sequence_8 = { 8994242c040000 8b542418 68f0060000 50 51 89942444040000 }
            // n = 6, score = 200
            //   8994242c040000       | mov                 dword ptr [esp + 0x42c], edx
            //   8b542418             | mov                 edx, dword ptr [esp + 0x18]
            //   68f0060000           | push                0x6f0
            //   50                   | push                eax
            //   51                   | push                ecx
            //   89942444040000       | mov                 dword ptr [esp + 0x444], edx

        $sequence_9 = { 6689442422 ff15???????? 8bf0 83feff 0f8493000000 8d442408 50 }
            // n = 7, score = 200
            //   6689442422           | mov                 word ptr [esp + 0x22], ax
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   83feff               | cmp                 esi, -1
            //   0f8493000000         | je                  0x99
            //   8d442408             | lea                 eax, [esp + 8]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 368640
}