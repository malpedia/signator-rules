rule win_silence_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.silence."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.silence"
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
        $sequence_0 = { 50 6a00 6a00 68???????? c745fc00000000 }
            // n = 5, score = 1800
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   68????????           |                     
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0

        $sequence_1 = { 8a4801 40 84c9 75f4 eb05 803800 }
            // n = 6, score = 1800
            //   8a4801               | mov                 cl, byte ptr [eax + 1]
            //   40                   | inc                 eax
            //   84c9                 | test                cl, cl
            //   75f4                 | jne                 0xfffffff6
            //   eb05                 | jmp                 7
            //   803800               | cmp                 byte ptr [eax], 0

        $sequence_2 = { cc 8325????????00 c3 6a08 68???????? e8???????? e8???????? }
            // n = 7, score = 1800
            //   cc                   | int3                
            //   8325????????00       |                     
            //   c3                   | ret                 
            //   6a08                 | push                8
            //   68????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     

        $sequence_3 = { 50 683f020f00 6a00 68???????? 6801000080 ff15???????? 68???????? }
            // n = 7, score = 1700
            //   50                   | push                eax
            //   683f020f00           | push                0xf023f
            //   6a00                 | push                0
            //   68????????           |                     
            //   6801000080           | push                0x80000001
            //   ff15????????         |                     
            //   68????????           |                     

        $sequence_4 = { 6801000080 ff15???????? 56 8d85f8feffff 50 }
            // n = 5, score = 1600
            //   6801000080           | push                0x80000001
            //   ff15????????         |                     
            //   56                   | push                esi
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]
            //   50                   | push                eax

        $sequence_5 = { 68???????? ffd6 8b45fc 85c0 }
            // n = 4, score = 1600
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   85c0                 | test                eax, eax

        $sequence_6 = { 3b0d???????? 7502 f3c3 e9???????? e8???????? e9???????? 6a14 }
            // n = 7, score = 1600
            //   3b0d????????         |                     
            //   7502                 | jne                 4
            //   f3c3                 | ret                 
            //   e9????????           |                     
            //   e8????????           |                     
            //   e9????????           |                     
            //   6a14                 | push                0x14

        $sequence_7 = { ff15???????? 6a00 6800000004 6a00 }
            // n = 4, score = 1600
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6800000004           | push                0x4000000
            //   6a00                 | push                0

        $sequence_8 = { 5e 5b 5d c3 c60200 }
            // n = 5, score = 1400
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   c60200               | mov                 byte ptr [edx], 0

        $sequence_9 = { eb0d 803800 7408 8a5a01 42 84db }
            // n = 6, score = 1400
            //   eb0d                 | jmp                 0xf
            //   803800               | cmp                 byte ptr [eax], 0
            //   7408                 | je                  0xa
            //   8a5a01               | mov                 bl, byte ptr [edx + 1]
            //   42                   | inc                 edx
            //   84db                 | test                bl, bl

        $sequence_10 = { 3acb 740a 8a4801 40 }
            // n = 4, score = 1400
            //   3acb                 | cmp                 cl, bl
            //   740a                 | je                  0xc
            //   8a4801               | mov                 cl, byte ptr [eax + 1]
            //   40                   | inc                 eax

        $sequence_11 = { 8bec 51 56 8b35???????? 6a00 6a00 6a00 }
            // n = 7, score = 1400
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   56                   | push                esi
            //   8b35????????         |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_12 = { 8bd8 68???????? 53 ff15???????? 6a00 6a00 6a00 }
            // n = 7, score = 1400
            //   8bd8                 | mov                 ebx, eax
            //   68????????           |                     
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_13 = { 40 84c9 75f4 eb0d 803800 7408 }
            // n = 6, score = 1400
            //   40                   | inc                 eax
            //   84c9                 | test                cl, cl
            //   75f4                 | jne                 0xfffffff6
            //   eb0d                 | jmp                 0xf
            //   803800               | cmp                 byte ptr [eax], 0
            //   7408                 | je                  0xa

        $sequence_14 = { 50 50 50 50 8d45fc 50 6a00 }
            // n = 7, score = 1400
            //   50                   | push                eax
            //   50                   | push                eax
            //   50                   | push                eax
            //   50                   | push                eax
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   6a00                 | push                0

        $sequence_15 = { 56 ff15???????? 8b85b8f7ffff 85c0 75b6 }
            // n = 5, score = 1200
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8b85b8f7ffff         | mov                 eax, dword ptr [ebp - 0x848]
            //   85c0                 | test                eax, eax
            //   75b6                 | jne                 0xffffffb8

        $sequence_16 = { 8d85b8f7ffff 50 6800080000 8d85bcf7ffff 50 56 ff15???????? }
            // n = 7, score = 1200
            //   8d85b8f7ffff         | lea                 eax, [ebp - 0x848]
            //   50                   | push                eax
            //   6800080000           | push                0x800
            //   8d85bcf7ffff         | lea                 eax, [ebp - 0x844]
            //   50                   | push                eax
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_17 = { 6a03 68000000c0 ffb5b0f7ffff ff15???????? }
            // n = 4, score = 1200
            //   6a03                 | push                3
            //   68000000c0           | push                0xc0000000
            //   ffb5b0f7ffff         | push                dword ptr [ebp - 0x850]
            //   ff15????????         |                     

        $sequence_18 = { ff5210 8b17 8bcf ff5208 }
            // n = 4, score = 1100
            //   ff5210               | call                dword ptr [edx + 0x10]
            //   8b17                 | mov                 edx, dword ptr [edi]
            //   8bcf                 | mov                 ecx, edi
            //   ff5208               | call                dword ptr [edx + 8]

        $sequence_19 = { ff5004 8b46f8 0346f4 57 ff7508 }
            // n = 5, score = 1100
            //   ff5004               | call                dword ptr [eax + 4]
            //   8b46f8               | mov                 eax, dword ptr [esi - 8]
            //   0346f4               | add                 eax, dword ptr [esi - 0xc]
            //   57                   | push                edi
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_20 = { 8b03 8d8df8fbffff 51 ffb5f0fbffff }
            // n = 4, score = 1100
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   8d8df8fbffff         | lea                 ecx, [ebp - 0x408]
            //   51                   | push                ecx
            //   ffb5f0fbffff         | push                dword ptr [ebp - 0x410]

        $sequence_21 = { 8d8dfcfbffff 51 ffb5f0fbffff 8bcb }
            // n = 4, score = 1100
            //   8d8dfcfbffff         | lea                 ecx, [ebp - 0x404]
            //   51                   | push                ecx
            //   ffb5f0fbffff         | push                dword ptr [ebp - 0x410]
            //   8bcb                 | mov                 ecx, ebx

        $sequence_22 = { 8b35???????? ffd6 ff7704 ffd6 ff770c ffd6 ff7708 }
            // n = 7, score = 1100
            //   8b35????????         |                     
            //   ffd6                 | call                esi
            //   ff7704               | push                dword ptr [edi + 4]
            //   ffd6                 | call                esi
            //   ff770c               | push                dword ptr [edi + 0xc]
            //   ffd6                 | call                esi
            //   ff7708               | push                dword ptr [edi + 8]

        $sequence_23 = { 85c9 7412 8b01 52 8d95f0fdffff }
            // n = 5, score = 1100
            //   85c9                 | test                ecx, ecx
            //   7412                 | je                  0x14
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   52                   | push                edx
            //   8d95f0fdffff         | lea                 edx, [ebp - 0x210]

        $sequence_24 = { e8???????? 83c41c 895ef8 897ef0 5b 5f }
            // n = 6, score = 1100
            //   e8????????           |                     
            //   83c41c               | add                 esp, 0x1c
            //   895ef8               | mov                 dword ptr [esi - 8], ebx
            //   897ef0               | mov                 dword ptr [esi - 0x10], edi
            //   5b                   | pop                 ebx
            //   5f                   | pop                 edi

        $sequence_25 = { 8b95ecfdffff 03fa 8bb5e8fdffff 3bf7 }
            // n = 4, score = 1100
            //   8b95ecfdffff         | mov                 edx, dword ptr [ebp - 0x214]
            //   03fa                 | add                 edi, edx
            //   8bb5e8fdffff         | mov                 esi, dword ptr [ebp - 0x218]
            //   3bf7                 | cmp                 esi, edi

        $sequence_26 = { 750b 68???????? ff15???????? ff35???????? }
            // n = 4, score = 400
            //   750b                 | jne                 0xd
            //   68????????           |                     
            //   ff15????????         |                     
            //   ff35????????         |                     

        $sequence_27 = { 68???????? ff15???????? c20800 53 8b1d???????? }
            // n = 5, score = 400
            //   68????????           |                     
            //   ff15????????         |                     
            //   c20800               | ret                 8
            //   53                   | push                ebx
            //   8b1d????????         |                     

        $sequence_28 = { c705????????03000000 c705????????00000000 c705????????04000000 ff15???????? 85c0 750b }
            // n = 6, score = 400
            //   c705????????03000000     |     
            //   c705????????00000000     |     
            //   c705????????04000000     |     
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   750b                 | jne                 0xd

        $sequence_29 = { ffd3 8b3d???????? 85c0 7507 68???????? }
            // n = 5, score = 400
            //   ffd3                 | call                ebx
            //   8b3d????????         |                     
            //   85c0                 | test                eax, eax
            //   7507                 | jne                 9
            //   68????????           |                     

        $sequence_30 = { 7507 68???????? ffd7 6a00 6a00 6a01 6a00 }
            // n = 7, score = 400
            //   7507                 | jne                 9
            //   68????????           |                     
            //   ffd7                 | call                edi
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   6a00                 | push                0

        $sequence_31 = { c705????????02000000 c705????????00000000 c705????????00000000 c705????????00000000 ffd3 8b3d???????? }
            // n = 6, score = 400
            //   c705????????02000000     |     
            //   c705????????00000000     |     
            //   c705????????00000000     |     
            //   c705????????00000000     |     
            //   ffd3                 | call                ebx
            //   8b3d????????         |                     

        $sequence_32 = { 68???????? 68???????? ff15???????? a3???????? 85c0 750e 68???????? }
            // n = 7, score = 400
            //   68????????           |                     
            //   68????????           |                     
            //   ff15????????         |                     
            //   a3????????           |                     
            //   85c0                 | test                eax, eax
            //   750e                 | jne                 0x10
            //   68????????           |                     

        $sequence_33 = { 8bec ff4d08 755d 833d????????04 }
            // n = 4, score = 400
            //   8bec                 | mov                 ebp, esp
            //   ff4d08               | dec                 dword ptr [ebp + 8]
            //   755d                 | jne                 0x5f
            //   833d????????04       |                     

        $sequence_34 = { ff15???????? 68c0d40100 ff15???????? e9???????? }
            // n = 4, score = 400
            //   ff15????????         |                     
            //   68c0d40100           | push                0x1d4c0
            //   ff15????????         |                     
            //   e9????????           |                     

        $sequence_35 = { 0fbf45f0 3b85c8feffff 7e0c c785c4feffff01000000 eb0a c785c4feffff00000000 8b0d???????? }
            // n = 7, score = 100
            //   0fbf45f0             | movsx               eax, word ptr [ebp - 0x10]
            //   3b85c8feffff         | cmp                 eax, dword ptr [ebp - 0x138]
            //   7e0c                 | jle                 0xe
            //   c785c4feffff01000000     | mov    dword ptr [ebp - 0x13c], 1
            //   eb0a                 | jmp                 0xc
            //   c785c4feffff00000000     | mov    dword ptr [ebp - 0x13c], 0
            //   8b0d????????         |                     

        $sequence_36 = { d3f8 2305???????? a3???????? 837de800 7418 0fbe4dfe 0fbe55ff }
            // n = 7, score = 100
            //   d3f8                 | sar                 eax, cl
            //   2305????????         |                     
            //   a3????????           |                     
            //   837de800             | cmp                 dword ptr [ebp - 0x18], 0
            //   7418                 | je                  0x1a
            //   0fbe4dfe             | movsx               ecx, byte ptr [ebp - 2]
            //   0fbe55ff             | movsx               edx, byte ptr [ebp - 1]

        $sequence_37 = { 890d???????? 0fb655fa 8bc2 0faf05???????? 99 b98c020000 f7f9 }
            // n = 7, score = 100
            //   890d????????         |                     
            //   0fb655fa             | movzx               edx, byte ptr [ebp - 6]
            //   8bc2                 | mov                 eax, edx
            //   0faf05????????       |                     
            //   99                   | cdq                 
            //   b98c020000           | mov                 ecx, 0x28c
            //   f7f9                 | idiv                ecx

        $sequence_38 = { 8d85e4f7ffff 50 8b4df8 51 ff15???????? 8945e8 837de800 }
            // n = 7, score = 100
            //   8d85e4f7ffff         | lea                 eax, [ebp - 0x81c]
            //   50                   | push                eax
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   837de800             | cmp                 dword ptr [ebp - 0x18], 0

        $sequence_39 = { d3e2 3355e8 2315???????? 8915???????? a1???????? 0faf45e8 }
            // n = 6, score = 100
            //   d3e2                 | shl                 edx, cl
            //   3355e8               | xor                 edx, dword ptr [ebp - 0x18]
            //   2315????????         |                     
            //   8915????????         |                     
            //   a1????????           |                     
            //   0faf45e8             | imul                eax, dword ptr [ebp - 0x18]

    condition:
        7 of them and filesize < 70128640
}