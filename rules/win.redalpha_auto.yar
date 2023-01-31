rule win_redalpha_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.redalpha."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redalpha"
        malpedia_rule_date = "20230124"
        malpedia_hash = "2ee0eebba83dce3d019a90519f2f972c0fcf9686"
        malpedia_version = "20230125"
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
        $sequence_0 = { c0e304 0fb6c3 50 68???????? }
            // n = 4, score = 400
            //   c0e304               | mov                 eax, dword ptr [ebx + 0xbac]
            //   0fb6c3               | inc                 edx
            //   50                   | mov                 dword ptr [ebx + eax*4 + 0xba8], eax
            //   68????????           |                     

        $sequence_1 = { 50 e8???????? 83c40c c0e304 0fb6c3 }
            // n = 5, score = 400
            //   50                   | cmp                 eax, 3
            //   e8????????           |                     
            //   83c40c               | jb                  0xd0
            //   c0e304               | mov                 eax, dword ptr [ebx + 0x94]
            //   0fb6c3               | test                eax, eax

        $sequence_2 = { ffc3 81fbe8030000 7cd1 eb74 c785903b010001000000 }
            // n = 5, score = 300
            //   ffc3                 | jbe                 0x3a
            //   81fbe8030000         | dec                 eax
            //   7cd1                 | lea                 ebx, [ebp + 0x2c0]
            //   eb74                 | nop                 dword ptr [eax]
            //   c785903b010001000000     | dec    eax

        $sequence_3 = { 8b4004 c744309048d24300 8b07 8b4804 }
            // n = 4, score = 300
            //   8b4004               | mov                 ecx, dword ptr [eax + 4]
            //   c744309048d24300     | lea                 eax, [ecx - 0x18]
            //   8b07                 | mov                 dword ptr [ecx + edx - 0x1c], eax
            //   8b4804               | mov                 eax, dword ptr [eax + 4]

        $sequence_4 = { 8b3f ff750c 53 6aff }
            // n = 4, score = 300
            //   8b3f                 | add                 esp, 0xc
            //   ff750c               | shl                 bl, 4
            //   53                   | movzx               eax, bl
            //   6aff                 | push                eax

        $sequence_5 = { 0fb7542448 0fb744244c 440fb7542446 440fb74c2442 }
            // n = 4, score = 300
            //   0fb7542448           | dec                 esp
            //   0fb744244c           | mov                 dword ptr [esp + 0x58], edi
            //   440fb7542446         | jne                 0x19
            //   440fb74c2442         | inc                 ecx

        $sequence_6 = { 4c89a5a0010000 83bd403b010000 7631 488d9dc0020000 0f1f8000000000 }
            // n = 5, score = 300
            //   4c89a5a0010000       | dec                 eax
            //   83bd403b010000       | mov                 eax, dword ptr [ebx + 0x68]
            //   7631                 | dec                 ecx
            //   488d9dc0020000       | mov                 word ptr [eax + ecx*2], bp
            //   0f1f8000000000       | inc                 esp

        $sequence_7 = { 488d842460010000 4889442438 488d442430 48898424b0020000 4533c9 }
            // n = 5, score = 300
            //   488d842460010000     | mov                 dword ptr [esp + 0x70], esi
            //   4889442438           | dec                 esp
            //   488d442430           | mov                 dword ptr [esp + 0x68], ebp
            //   48898424b0020000     | dec                 esp
            //   4533c9               | mov                 dword ptr [esp + 0x60], esi

        $sequence_8 = { 4183f803 0f82ca000000 8b8394000000 85c0 0f84bc000000 4c8b4b50 }
            // n = 6, score = 300
            //   4183f803             | mov                 dword ptr [esp], 0xc
            //   0f82ca000000         | inc                 ebx
            //   8b8394000000         | cmp                 ebx, 0x3e8
            //   85c0                 | jl                  0xffffffd9
            //   0f84bc000000         | jmp                 0x7e
            //   4c8b4b50             | mov                 dword ptr [ebp + 0x13b90], 1

        $sequence_9 = { 8b4004 c74408e840d24300 8b41e8 8b5004 }
            // n = 4, score = 300
            //   8b4004               | push                eax
            //   c74408e840d24300     | mov                 edi, dword ptr [esi]
            //   8b41e8               | mov                 ecx, esi
            //   8b5004               | mov                 ecx, dword ptr [ebp - 8]

        $sequence_10 = { 418b5c2440 448db9fffeffff 418b4c2468 4d03f8 458b5c2444 8bc2 }
            // n = 6, score = 300
            //   418b5c2440           | inc                 ecx
            //   448db9fffeffff       | mov                 ebx, dword ptr [esp + 0x40]
            //   418b4c2468           | inc                 esp
            //   4d03f8               | lea                 edi, [ecx - 0x101]
            //   458b5c2444           | inc                 ecx
            //   8bc2                 | mov                 ecx, dword ptr [esp + 0x68]

        $sequence_11 = { 8b4004 c744309040d24300 8b4690 8b4804 }
            // n = 4, score = 300
            //   8b4004               | push                0
            //   c744309040d24300     | mov                 eax, dword ptr [eax + 4]
            //   8b4690               | mov                 dword ptr [eax + ecx - 0x18], 0x43d240
            //   8b4804               | mov                 eax, dword ptr [ecx - 0x18]

        $sequence_12 = { 4889742470 4c896c2468 4c89742460 4c897c2458 7508 41c704240c000000 }
            // n = 6, score = 300
            //   4889742470           | mov                 eax, dword ptr [ebx + 0x74]
            //   4c896c2468           | dec                 eax
            //   4c89742460           | mov                 ecx, dword ptr [ebx + 0x68]
            //   4c897c2458           | dec                 esp
            //   7508                 | mov                 dword ptr [ebp + 0x1a0], esp
            //   41c704240c000000     | cmp                 dword ptr [ebp + 0x13b40], 0

        $sequence_13 = { 8b4004 c74410e840d24300 8b06 8b4804 }
            // n = 4, score = 300
            //   8b4004               | sub                 dword ptr [ecx], edi
            //   c74410e840d24300     | mov                 edi, dword ptr [edi]
            //   8b06                 | push                dword ptr [ebp + 0xc]
            //   8b4804               | push                ebx

        $sequence_14 = { 8b3e 8bce e8???????? 8b4df8 2b3e 8b35???????? }
            // n = 6, score = 300
            //   8b3e                 | push                eax
            //   8bce                 | push                eax
            //   e8????????           |                     
            //   8b4df8               | add                 esp, 0xc
            //   2b3e                 | shl                 bl, 4
            //   8b35????????         |                     

        $sequence_15 = { 488b4368 ffc9 66892c48 448b4374 488b4b68 }
            // n = 5, score = 300
            //   488b4368             | dec                 ebp
            //   ffc9                 | add                 edi, eax
            //   66892c48             | inc                 ebp
            //   448b4374             | mov                 ebx, dword ptr [esp + 0x44]
            //   488b4b68             | mov                 eax, edx

        $sequence_16 = { 7459 6a00 53 ff15???????? 8bf8 85ff }
            // n = 6, score = 100
            //   7459                 | je                  0x5b
            //   6a00                 | push                0
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi

        $sequence_17 = { 8b85e8fbffff 85c0 742b 8d8decfbffff 51 50 }
            // n = 6, score = 100
            //   8b85e8fbffff         | mov                 eax, dword ptr [ebp - 0x418]
            //   85c0                 | test                eax, eax
            //   742b                 | je                  0x2d
            //   8d8decfbffff         | lea                 ecx, [ebp - 0x414]
            //   51                   | push                ecx
            //   50                   | push                eax

        $sequence_18 = { 45 3bc3 896c2418 72da 8b2c9df8464000 8b4e04 }
            // n = 6, score = 100
            //   45                   | push                eax
            //   3bc3                 | add                 esp, 0xc
            //   896c2418             | shl                 bl, 4
            //   72da                 | movzx               eax, bl
            //   8b2c9df8464000       | push                eax
            //   8b4e04               | push                eax

        $sequence_19 = { 8d55c0 b9???????? 0f4355c0 e8???????? 83f801 7519 }
            // n = 6, score = 100
            //   8d55c0               | lea                 edx, [ebp - 0x40]
            //   b9????????           |                     
            //   0f4355c0             | cmovae              edx, dword ptr [ebp - 0x40]
            //   e8????????           |                     
            //   83f801               | cmp                 eax, 1
            //   7519                 | jne                 0x1b

        $sequence_20 = { 5e 5b 8be5 5d c20800 8d4601 }
            // n = 6, score = 100
            //   5e                   | add                 esp, 0xc
            //   5b                   | shl                 bl, 4
            //   8be5                 | movzx               eax, bl
            //   5d                   | push                eax
            //   c20800               | add                 esp, 0xc
            //   8d4601               | shl                 bl, 4

        $sequence_21 = { 750b 8b450c 50 ffd6 }
            // n = 4, score = 100
            //   750b                 | shl                 bl, 4
            //   8b450c               | movzx               eax, bl
            //   50                   | push                eax
            //   ffd6                 | push                eax

        $sequence_22 = { 8b4d0c 8bd9 57 8b7d08 81f900280000 894df8 }
            // n = 6, score = 100
            //   8b4d0c               | movzx               eax, bl
            //   8bd9                 | add                 esp, 0xc
            //   57                   | shl                 bl, 4
            //   8b7d08               | movzx               eax, bl
            //   81f900280000         | push                eax
            //   894df8               | add                 esp, 0xc

        $sequence_23 = { 8b0c9530744100 8844192e 8b049530744100 804c182d04 }
            // n = 4, score = 100
            //   8b0c9530744100       | mov                 ecx, dword ptr [edx*4 + 0x417430]
            //   8844192e             | mov                 byte ptr [ecx + ebx + 0x2e], al
            //   8b049530744100       | mov                 eax, dword ptr [edx*4 + 0x417430]
            //   804c182d04           | or                  byte ptr [eax + ebx + 0x2d], 4

        $sequence_24 = { ffd3 57 ffd3 56 ffd3 57 ffd3 }
            // n = 7, score = 100
            //   ffd3                 | call                ebx
            //   57                   | push                edi
            //   ffd3                 | call                ebx
            //   56                   | push                esi
            //   ffd3                 | call                ebx
            //   57                   | push                edi
            //   ffd3                 | call                ebx

        $sequence_25 = { 53 8b1d???????? 755f 6a00 6a00 56 ff15???????? }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   8b1d????????         |                     
            //   755f                 | jne                 0x61
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_26 = { 50 8d5f14 53 ff15???????? 8bc8 c645fc00 }
            // n = 6, score = 100
            //   50                   | add                 esp, 0xc
            //   8d5f14               | shl                 bl, 4
            //   53                   | movzx               eax, bl
            //   ff15????????         |                     
            //   8bc8                 | push                eax
            //   c645fc00             | add                 esp, 0xc

        $sequence_27 = { 8d4dc0 c745fc00000000 e8???????? 8d4dd8 e8???????? 6a1b 51 }
            // n = 7, score = 100
            //   8d4dc0               | lea                 ecx, [ebp - 0x40]
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   e8????????           |                     
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   e8????????           |                     
            //   6a1b                 | push                0x1b
            //   51                   | push                ecx

        $sequence_28 = { db2d???????? b802000000 833d????????00 0f85b00a0000 8d0df02e4100 ba1b000000 }
            // n = 6, score = 100
            //   db2d????????         |                     
            //   b802000000           | mov                 eax, 2
            //   833d????????00       |                     
            //   0f85b00a0000         | jne                 0xab6
            //   8d0df02e4100         | lea                 ecx, [0x412ef0]
            //   ba1b000000           | mov                 edx, 0x1b

        $sequence_29 = { ffb7ac000000 ff15???????? ffb7ac000000 ff15???????? 6a00 }
            // n = 5, score = 100
            //   ffb7ac000000         | shl                 bl, 4
            //   ff15????????         |                     
            //   ffb7ac000000         | movzx               eax, bl
            //   ff15????????         |                     
            //   6a00                 | push                eax

    condition:
        7 of them and filesize < 606208
}