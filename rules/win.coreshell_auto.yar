rule win_coreshell_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.coreshell."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.coreshell"
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
        $sequence_0 = { 56 ff15???????? 83c40c 3bc6 }
            // n = 4, score = 1000
            //   56                   | push                esi
            //   ff15????????         |                     
            //   83c40c               | add                 esp, 0xc
            //   3bc6                 | cmp                 eax, esi

        $sequence_1 = { 56 6810270000 ff15???????? be06000000 }
            // n = 4, score = 1000
            //   56                   | push                esi
            //   6810270000           | push                0x2710
            //   ff15????????         |                     
            //   be06000000           | mov                 esi, 6

        $sequence_2 = { be06000000 e8???????? 85c0 7401 }
            // n = 4, score = 1000
            //   be06000000           | mov                 esi, 6
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7401                 | je                  3

        $sequence_3 = { 68???????? 52 ffd7 ffd0 }
            // n = 4, score = 1000
            //   68????????           |                     
            //   52                   | push                edx
            //   ffd7                 | call                edi
            //   ffd0                 | call                eax

        $sequence_4 = { 8b0d???????? 8b15???????? 6a01 51 68???????? 52 }
            // n = 6, score = 800
            //   8b0d????????         |                     
            //   8b15????????         |                     
            //   6a01                 | push                1
            //   51                   | push                ecx
            //   68????????           |                     
            //   52                   | push                edx

        $sequence_5 = { 8d041e 50 57 6a08 51 }
            // n = 5, score = 800
            //   8d041e               | lea                 eax, [esi + ebx]
            //   50                   | push                eax
            //   57                   | push                edi
            //   6a08                 | push                8
            //   51                   | push                ecx

        $sequence_6 = { c20400 50 a1???????? 6a00 50 }
            // n = 5, score = 800
            //   c20400               | ret                 4
            //   50                   | push                eax
            //   a1????????           |                     
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_7 = { 6a00 ff15???????? 8bf0 ff15???????? 50 68???????? }
            // n = 6, score = 800
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     
            //   50                   | push                eax
            //   68????????           |                     

        $sequence_8 = { 6a08 51 ff15???????? 8bf8 85ff 750a 5f }
            // n = 7, score = 800
            //   6a08                 | push                8
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi
            //   750a                 | jne                 0xc
            //   5f                   | pop                 edi

        $sequence_9 = { 6804010000 6a08 8b15???????? 52 }
            // n = 4, score = 800
            //   6804010000           | push                0x104
            //   6a08                 | push                8
            //   8b15????????         |                     
            //   52                   | push                edx

        $sequence_10 = { ff15???????? ffd0 85c0 7508 ff15???????? }
            // n = 5, score = 700
            //   ff15????????         |                     
            //   ffd0                 | call                eax
            //   85c0                 | test                eax, eax
            //   7508                 | jne                 0xa
            //   ff15????????         |                     

        $sequence_11 = { 85c0 7402 eb14 c745f000000000 68e0930400 }
            // n = 5, score = 700
            //   85c0                 | test                eax, eax
            //   7402                 | je                  4
            //   eb14                 | jmp                 0x16
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   68e0930400           | push                0x493e0

        $sequence_12 = { 50 a3???????? ffd6 a3???????? a1???????? 68???????? 50 }
            // n = 7, score = 700
            //   50                   | push                eax
            //   a3????????           |                     
            //   ffd6                 | call                esi
            //   a3????????           |                     
            //   a1????????           |                     
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_13 = { 8d4c2400 56 51 6a00 }
            // n = 4, score = 700
            //   8d4c2400             | lea                 ecx, [esp]
            //   56                   | push                esi
            //   51                   | push                ecx
            //   6a00                 | push                0

        $sequence_14 = { 8bf1 8b4604 85c0 7407 50 ff15???????? 8b36 }
            // n = 7, score = 700
            //   8bf1                 | mov                 esi, ecx
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b36                 | mov                 esi, dword ptr [esi]

        $sequence_15 = { 68???????? 50 ffd6 6a00 6a00 6a00 }
            // n = 6, score = 600
            //   68????????           |                     
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_16 = { 6a00 8bf1 50 c744240c00000000 ff15???????? 85c0 }
            // n = 6, score = 600
            //   6a00                 | push                0
            //   8bf1                 | mov                 esi, ecx
            //   50                   | push                eax
            //   c744240c00000000     | mov                 dword ptr [esp + 0xc], 0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_17 = { 6800080000 8d85fcefffff 50 ff15???????? }
            // n = 4, score = 600
            //   6800080000           | push                0x800
            //   8d85fcefffff         | lea                 eax, [ebp - 0x1004]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_18 = { 51 8b0d???????? 52 50 57 68???????? 51 }
            // n = 7, score = 600
            //   51                   | push                ecx
            //   8b0d????????         |                     
            //   52                   | push                edx
            //   50                   | push                eax
            //   57                   | push                edi
            //   68????????           |                     
            //   51                   | push                ecx

        $sequence_19 = { 83c424 8d85f4fdffff 50 ff15???????? }
            // n = 4, score = 500
            //   83c424               | add                 esp, 0x24
            //   8d85f4fdffff         | lea                 eax, [ebp - 0x20c]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_20 = { 68???????? 8985f0fdffff 8d85f4fdffff 6804010000 50 }
            // n = 5, score = 500
            //   68????????           |                     
            //   8985f0fdffff         | mov                 dword ptr [ebp - 0x210], eax
            //   8d85f4fdffff         | lea                 eax, [ebp - 0x20c]
            //   6804010000           | push                0x104
            //   50                   | push                eax

        $sequence_21 = { 81e1ffff0000 81e1ffff0000 81e1ff000000 81e1ff000000 }
            // n = 4, score = 500
            //   81e1ffff0000         | and                 ecx, 0xffff
            //   81e1ffff0000         | and                 ecx, 0xffff
            //   81e1ff000000         | and                 ecx, 0xff
            //   81e1ff000000         | and                 ecx, 0xff

        $sequence_22 = { 80fb06 7312 ff15???????? 0fb6cb 03cf 880431 }
            // n = 6, score = 500
            //   80fb06               | cmp                 bl, 6
            //   7312                 | jae                 0x14
            //   ff15????????         |                     
            //   0fb6cb               | movzx               ecx, bl
            //   03cf                 | add                 ecx, edi
            //   880431               | mov                 byte ptr [ecx + esi], al

        $sequence_23 = { 68???????? 6a00 6a00 a3???????? ff15???????? a3???????? b801000000 }
            // n = 7, score = 500
            //   68????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   a3????????           |                     
            //   ff15????????         |                     
            //   a3????????           |                     
            //   b801000000           | mov                 eax, 1

        $sequence_24 = { 52 e8???????? 83c408 33c0 8b4df0 64890d00000000 5f }
            // n = 7, score = 500
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   33c0                 | xor                 eax, eax
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   5f                   | pop                 edi

        $sequence_25 = { a1???????? 50 68???????? 8b0d???????? 51 ff15???????? ffd0 }
            // n = 7, score = 400
            //   a1????????           |                     
            //   50                   | push                eax
            //   68????????           |                     
            //   8b0d????????         |                     
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   ffd0                 | call                eax

        $sequence_26 = { 6888130000 ff15???????? c745f000000000 c745f400000000 }
            // n = 4, score = 400
            //   6888130000           | push                0x1388
            //   ff15????????         |                     
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0

        $sequence_27 = { ba00080000 2bd0 52 8d85fcefffff }
            // n = 4, score = 400
            //   ba00080000           | mov                 edx, 0x800
            //   2bd0                 | sub                 edx, eax
            //   52                   | push                edx
            //   8d85fcefffff         | lea                 eax, [ebp - 0x1004]

        $sequence_28 = { 50 ff15???????? 8d8c45fcefffff 51 }
            // n = 4, score = 400
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d8c45fcefffff       | lea                 ecx, [ebp + eax*2 - 0x1004]
            //   51                   | push                ecx

        $sequence_29 = { 51 ff15???????? 83c414 8d95f4fdffff }
            // n = 4, score = 400
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   83c414               | add                 esp, 0x14
            //   8d95f4fdffff         | lea                 edx, [ebp - 0x20c]

        $sequence_30 = { 81e2ffff0000 81e2ffff0000 c1ea08 81e2ff000000 }
            // n = 4, score = 400
            //   81e2ffff0000         | and                 edx, 0xffff
            //   81e2ffff0000         | and                 edx, 0xffff
            //   c1ea08               | shr                 edx, 8
            //   81e2ff000000         | and                 edx, 0xff

        $sequence_31 = { e8???????? 8be8 8b442410 50 e8???????? }
            // n = 5, score = 400
            //   e8????????           |                     
            //   8be8                 | mov                 ebp, eax
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_32 = { 50 ff15???????? 83c414 8d8df4fdffff 51 ff15???????? }
            // n = 6, score = 400
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c414               | add                 esp, 0x14
            //   8d8df4fdffff         | lea                 ecx, [ebp - 0x20c]
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_33 = { 56 51 56 6a01 }
            // n = 4, score = 400
            //   56                   | push                esi
            //   51                   | push                ecx
            //   56                   | push                esi
            //   6a01                 | push                1

        $sequence_34 = { ffd6 ffd0 68???????? a3???????? }
            // n = 4, score = 300
            //   ffd6                 | call                esi
            //   ffd0                 | call                eax
            //   68????????           |                     
            //   a3????????           |                     

        $sequence_35 = { ff35???????? ff15???????? 0305???????? 50 ff15???????? a1???????? 83c418 }
            // n = 7, score = 300
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   0305????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   a1????????           |                     
            //   83c418               | add                 esp, 0x18

        $sequence_36 = { 8b3d???????? 68???????? ffd7 8b35???????? 68???????? 50 a3???????? }
            // n = 7, score = 200
            //   8b3d????????         |                     
            //   68????????           |                     
            //   ffd7                 | call                edi
            //   8b35????????         |                     
            //   68????????           |                     
            //   50                   | push                eax
            //   a3????????           |                     

        $sequence_37 = { a3???????? ffd7 8bd8 68???????? 53 ffd6 }
            // n = 6, score = 200
            //   a3????????           |                     
            //   ffd7                 | call                edi
            //   8bd8                 | mov                 ebx, eax
            //   68????????           |                     
            //   53                   | push                ebx
            //   ffd6                 | call                esi

        $sequence_38 = { 5f 5b 5d c3 b81c000000 }
            // n = 5, score = 200
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   b81c000000           | mov                 eax, 0x1c

        $sequence_39 = { 8908 8b00 8b5004 8b35???????? }
            // n = 4, score = 200
            //   8908                 | mov                 dword ptr [eax], ecx
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8b5004               | mov                 edx, dword ptr [eax + 4]
            //   8b35????????         |                     

        $sequence_40 = { 8908 813800000000 0f94c2 8b35???????? 8b3d???????? 0faff6 }
            // n = 6, score = 200
            //   8908                 | mov                 dword ptr [eax], ecx
            //   813800000000         | cmp                 dword ptr [eax], 0
            //   0f94c2               | sete                dl
            //   8b35????????         |                     
            //   8b3d????????         |                     
            //   0faff6               | imul                esi, esi

        $sequence_41 = { 8908 8b15???????? 89d6 81c609000000 }
            // n = 4, score = 200
            //   8908                 | mov                 dword ptr [eax], ecx
            //   8b15????????         |                     
            //   89d6                 | mov                 esi, edx
            //   81c609000000         | add                 esi, 9

        $sequence_42 = { 29d6 01f0 a3???????? e9???????? }
            // n = 4, score = 200
            //   29d6                 | sub                 esi, edx
            //   01f0                 | add                 eax, esi
            //   a3????????           |                     
            //   e9????????           |                     

        $sequence_43 = { 29d6 0faff0 31d2 f7f6 }
            // n = 4, score = 200
            //   29d6                 | sub                 esi, edx
            //   0faff0               | imul                esi, eax
            //   31d2                 | xor                 edx, edx
            //   f7f6                 | div                 esi

        $sequence_44 = { ffd6 68???????? 53 a3???????? ffd6 68???????? a3???????? }
            // n = 7, score = 200
            //   ffd6                 | call                esi
            //   68????????           |                     
            //   53                   | push                ebx
            //   a3????????           |                     
            //   ffd6                 | call                esi
            //   68????????           |                     
            //   a3????????           |                     

        $sequence_45 = { bf04010000 57 6a08 ff35???????? ff15???????? }
            // n = 5, score = 200
            //   bf04010000           | mov                 edi, 0x104
            //   57                   | push                edi
            //   6a08                 | push                8
            //   ff35????????         |                     
            //   ff15????????         |                     

        $sequence_46 = { 5f 5d c3 89e0 c70010270000 }
            // n = 5, score = 200
            //   5f                   | pop                 edi
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   89e0                 | mov                 eax, esp
            //   c70010270000         | mov                 dword ptr [eax], 0x2710

        $sequence_47 = { 8908 813800000000 0f95c2 8b35???????? }
            // n = 4, score = 200
            //   8908                 | mov                 dword ptr [eax], ecx
            //   813800000000         | cmp                 dword ptr [eax], 0
            //   0f95c2               | setne               dl
            //   8b35????????         |                     

        $sequence_48 = { ff35???????? ff15???????? 8bd8 3bde 895dd0 7416 8d45e4 }
            // n = 7, score = 100
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax
            //   3bde                 | cmp                 ebx, esi
            //   895dd0               | mov                 dword ptr [ebp - 0x30], ebx
            //   7416                 | je                  0x18
            //   8d45e4               | lea                 eax, [ebp - 0x1c]

    condition:
        7 of them and filesize < 303100
}