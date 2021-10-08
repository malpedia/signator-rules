rule win_emotet_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.emotet."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet"
        malpedia_rule_date = "20211007"
        malpedia_hash = "e5b790e0f888f252d49063a1251ca60ec2832535"
        malpedia_version = "20211008"
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
        $sequence_0 = { 33c0 3903 5f 5e 0f95c0 5b 8be5 }
            // n = 7, score = 2400
            //   33c0                 | xor                 eax, eax
            //   3903                 | cmp                 dword ptr [ebx], eax
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   0f95c0               | setne               al
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp

        $sequence_1 = { 0fb7c0 83c020 eb03 0fb7c0 69d23f000100 }
            // n = 5, score = 2300
            //   0fb7c0               | movzx               eax, ax
            //   83c020               | add                 eax, 0x20
            //   eb03                 | jmp                 5
            //   0fb7c0               | movzx               eax, ax
            //   69d23f000100         | imul                edx, edx, 0x1003f

        $sequence_2 = { 8a01 3c30 7c04 3c39 7e13 }
            // n = 5, score = 2100
            //   8a01                 | mov                 al, byte ptr [ecx]
            //   3c30                 | cmp                 al, 0x30
            //   7c04                 | jl                  6
            //   3c39                 | cmp                 al, 0x39
            //   7e13                 | jle                 0x15

        $sequence_3 = { 7c04 3c5a 7e03 c60158 }
            // n = 4, score = 2100
            //   7c04                 | jl                  6
            //   3c5a                 | cmp                 al, 0x5a
            //   7e03                 | jle                 5
            //   c60158               | mov                 byte ptr [ecx], 0x58

        $sequence_4 = { 3c39 7e13 3c61 7c04 3c7a }
            // n = 5, score = 2100
            //   3c39                 | cmp                 al, 0x39
            //   7e13                 | jle                 0x15
            //   3c61                 | cmp                 al, 0x61
            //   7c04                 | jl                  6
            //   3c7a                 | cmp                 al, 0x7a

        $sequence_5 = { 3c7a 7e0b 3c41 7c04 3c5a }
            // n = 5, score = 2100
            //   3c7a                 | cmp                 al, 0x7a
            //   7e0b                 | jle                 0xd
            //   3c41                 | cmp                 al, 0x41
            //   7c04                 | jl                  6
            //   3c5a                 | cmp                 al, 0x5a

        $sequence_6 = { 8d5801 f6c30f 7406 83e3f0 }
            // n = 4, score = 2000
            //   8d5801               | lea                 ebx, dword ptr [eax + 1]
            //   f6c30f               | test                bl, 0xf
            //   7406                 | je                  8
            //   83e3f0               | and                 ebx, 0xfffffff0

        $sequence_7 = { 64a130000000 53 56 57 8b780c 8bd9 }
            // n = 6, score = 1900
            //   64a130000000         | mov                 eax, dword ptr fs:[0x30]
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b780c               | mov                 edi, dword ptr [eax + 0xc]
            //   8bd9                 | mov                 ebx, ecx

        $sequence_8 = { 8b16 8945fc 8d45f8 6a04 50 }
            // n = 5, score = 1900
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8d45f8               | lea                 eax, dword ptr [ebp - 8]
            //   6a04                 | push                4
            //   50                   | push                eax

        $sequence_9 = { 8b780c 8bd9 83c70c 8b37 }
            // n = 4, score = 1900
            //   8b780c               | mov                 edi, dword ptr [eax + 0xc]
            //   8bd9                 | mov                 ebx, ecx
            //   83c70c               | add                 edi, 0xc
            //   8b37                 | mov                 esi, dword ptr [edi]

        $sequence_10 = { 2b4770 8901 8b477c 85c0 7448 8b00 2b878c000000 }
            // n = 7, score = 1900
            //   2b4770               | sub                 eax, dword ptr [edi + 0x70]
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8b477c               | mov                 eax, dword ptr [edi + 0x7c]
            //   85c0                 | test                eax, eax
            //   7448                 | je                  0x4a
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   2b878c000000         | sub                 eax, dword ptr [edi + 0x8c]

        $sequence_11 = { 894dcc 8d4dc8 8945c8 8975d4 8955d8 }
            // n = 5, score = 1900
            //   894dcc               | mov                 dword ptr [ebp - 0x34], ecx
            //   8d4dc8               | lea                 ecx, dword ptr [ebp - 0x38]
            //   8945c8               | mov                 dword ptr [ebp - 0x38], eax
            //   8975d4               | mov                 dword ptr [ebp - 0x2c], esi
            //   8955d8               | mov                 dword ptr [ebp - 0x28], edx

        $sequence_12 = { 56 50 8b4774 03878c000000 50 ff15???????? 017758 }
            // n = 7, score = 1900
            //   56                   | push                esi
            //   50                   | push                eax
            //   8b4774               | mov                 eax, dword ptr [edi + 0x74]
            //   03878c000000         | add                 eax, dword ptr [edi + 0x8c]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   017758               | add                 dword ptr [edi + 0x58], esi

        $sequence_13 = { ff15???????? 017758 83c40c 29775c 8b477c 01b78c000000 }
            // n = 6, score = 1900
            //   ff15????????         |                     
            //   017758               | add                 dword ptr [edi + 0x58], esi
            //   83c40c               | add                 esp, 0xc
            //   29775c               | sub                 dword ptr [edi + 0x5c], esi
            //   8b477c               | mov                 eax, dword ptr [edi + 0x7c]
            //   01b78c000000         | add                 dword ptr [edi + 0x8c], esi

        $sequence_14 = { 56 8b4004 57 8d5801 }
            // n = 4, score = 1800
            //   56                   | push                esi
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   57                   | push                edi
            //   8d5801               | lea                 ebx, dword ptr [eax + 1]

        $sequence_15 = { c745fc04000000 50 8d45f8 81ca00000020 50 52 51 }
            // n = 7, score = 1800
            //   c745fc04000000       | mov                 dword ptr [ebp - 4], 4
            //   50                   | push                eax
            //   8d45f8               | lea                 eax, dword ptr [ebp - 8]
            //   81ca00000020         | or                  edx, 0x20000000
            //   50                   | push                eax
            //   52                   | push                edx
            //   51                   | push                ecx

        $sequence_16 = { c60158 41 803900 75dd }
            // n = 4, score = 1600
            //   c60158               | mov                 byte ptr [ecx], 0x58
            //   41                   | inc                 ecx
            //   803900               | cmp                 byte ptr [ecx], 0
            //   75dd                 | jne                 0xffffffdf

        $sequence_17 = { c1e807 46 83f87f 77f7 }
            // n = 4, score = 1600
            //   c1e807               | shr                 eax, 7
            //   46                   | inc                 esi
            //   83f87f               | cmp                 eax, 0x7f
            //   77f7                 | ja                  0xfffffff9

        $sequence_18 = { 7430 8d9b00000000 6683f841 720e }
            // n = 4, score = 1500
            //   7430                 | je                  0x32
            //   8d9b00000000         | lea                 ebx, dword ptr [ebx]
            //   6683f841             | cmp                 ax, 0x41
            //   720e                 | jb                  0x10

        $sequence_19 = { 8bd3 8b0f e8???????? 85c0 }
            // n = 4, score = 1400
            //   8bd3                 | mov                 edx, ebx
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_20 = { 880a 8bc1 c1e808 8d5204 c1e910 }
            // n = 5, score = 1300
            //   880a                 | mov                 byte ptr [edx], cl
            //   8bc1                 | mov                 eax, ecx
            //   c1e808               | shr                 eax, 8
            //   8d5204               | lea                 edx, dword ptr [edx + 4]
            //   c1e910               | shr                 ecx, 0x10

        $sequence_21 = { 8d5204 c1e910 8842fd 884afe c1e908 }
            // n = 5, score = 1300
            //   8d5204               | lea                 edx, dword ptr [edx + 4]
            //   c1e910               | shr                 ecx, 0x10
            //   8842fd               | mov                 byte ptr [edx - 3], al
            //   884afe               | mov                 byte ptr [edx - 2], cl
            //   c1e908               | shr                 ecx, 8

        $sequence_22 = { 83c104 894e04 8b00 85c0 }
            // n = 4, score = 1200
            //   83c104               | add                 ecx, 4
            //   894e04               | mov                 dword ptr [esi + 4], ecx
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   85c0                 | test                eax, eax

        $sequence_23 = { 7907 83c107 3bf7 72e8 }
            // n = 4, score = 1200
            //   7907                 | jns                 9
            //   83c107               | add                 ecx, 7
            //   3bf7                 | cmp                 esi, edi
            //   72e8                 | jb                  0xffffffea

        $sequence_24 = { 52 52 52 52 68???????? 52 }
            // n = 6, score = 1100
            //   52                   | push                edx
            //   52                   | push                edx
            //   52                   | push                edx
            //   52                   | push                edx
            //   68????????           |                     
            //   52                   | push                edx

        $sequence_25 = { 83f87f 760d 8d642400 c1e807 }
            // n = 4, score = 1000
            //   83f87f               | cmp                 eax, 0x7f
            //   760d                 | jbe                 0xf
            //   8d642400             | lea                 esp, dword ptr [esp]
            //   c1e807               | shr                 eax, 7

        $sequence_26 = { d3e7 83f841 7208 83f85a }
            // n = 4, score = 1000
            //   d3e7                 | shl                 edi, cl
            //   83f841               | cmp                 eax, 0x41
            //   7208                 | jb                  0xa
            //   83f85a               | cmp                 eax, 0x5a

        $sequence_27 = { b901000000 83f87f 7609 c1e807 41 }
            // n = 5, score = 900
            //   b901000000           | mov                 ecx, 1
            //   83f87f               | cmp                 eax, 0x7f
            //   7609                 | jbe                 0xb
            //   c1e807               | shr                 eax, 7
            //   41                   | inc                 ecx

        $sequence_28 = { 6a00 6aff 50 51 ff15???????? }
            // n = 5, score = 800
            //   6a00                 | push                0
            //   6aff                 | push                -1
            //   50                   | push                eax
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_29 = { 8b5d08 b8afa96e5e 56 57 }
            // n = 4, score = 800
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   b8afa96e5e           | mov                 eax, 0x5e6ea9af
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_30 = { 50 6a00 6a01 6a00 ff15???????? a3???????? }
            // n = 6, score = 800
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   a3????????           |                     

        $sequence_31 = { 83ec14 53 8b5d08 b8afa96e5e }
            // n = 4, score = 700
            //   83ec14               | sub                 esp, 0x14
            //   53                   | push                ebx
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   b8afa96e5e           | mov                 eax, 0x5e6ea9af

        $sequence_32 = { 84c0 7413 3c2e 740c }
            // n = 4, score = 700
            //   84c0                 | test                al, al
            //   7413                 | je                  0x15
            //   3c2e                 | cmp                 al, 0x2e
            //   740c                 | je                  0xe

        $sequence_33 = { 56 68400000f0 6a18 33f6 }
            // n = 4, score = 600
            //   56                   | push                esi
            //   68400000f0           | push                0xf0000040
            //   6a18                 | push                0x18
            //   33f6                 | xor                 esi, esi

        $sequence_34 = { 53 56 8bf1 bb00c34c84 }
            // n = 4, score = 600
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   bb00c34c84           | mov                 ebx, 0x844cc300

        $sequence_35 = { 50 56 6800800000 6a6a }
            // n = 4, score = 600
            //   50                   | push                eax
            //   56                   | push                esi
            //   6800800000           | push                0x8000
            //   6a6a                 | push                0x6a

        $sequence_36 = { 50 6a00 ff75fc 6800040000 6a00 6a00 6a00 }
            // n = 7, score = 600
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   6800040000           | push                0x400
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_37 = { 8b55e0 01ca 89d6 83c604 8b7de0 }
            // n = 5, score = 500
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]
            //   01ca                 | add                 edx, ecx
            //   89d6                 | mov                 esi, edx
            //   83c604               | add                 esi, 4
            //   8b7de0               | mov                 edi, dword ptr [ebp - 0x20]

        $sequence_38 = { 8b5508 befbffffff c600e9 29d6 }
            // n = 4, score = 500
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   befbffffff           | mov                 esi, 0xfffffffb
            //   c600e9               | mov                 byte ptr [eax], 0xe9
            //   29d6                 | sub                 esi, edx

        $sequence_39 = { 83c60c 8b7df4 8b4c0f0c 83f900 }
            // n = 4, score = 500
            //   83c60c               | add                 esi, 0xc
            //   8b7df4               | mov                 edi, dword ptr [ebp - 0xc]
            //   8b4c0f0c             | mov                 ecx, dword ptr [edi + ecx + 0xc]
            //   83f900               | cmp                 ecx, 0

        $sequence_40 = { 8a3c11 28df 883c11 81c2ff000000 }
            // n = 4, score = 500
            //   8a3c11               | mov                 bh, byte ptr [ecx + edx]
            //   28df                 | sub                 bh, bl
            //   883c11               | mov                 byte ptr [ecx + edx], bh
            //   81c2ff000000         | add                 edx, 0xff

        $sequence_41 = { 56 57 00b807000000 008b45fc33d2 00b871800780 00558b }
            // n = 6, score = 500
            //   56                   | push                esi
            //   57                   | push                edi
            //   00b807000000         | add                 byte ptr [eax + 7], bh
            //   008b45fc33d2         | add                 byte ptr [ebx - 0x2dcc03bb], cl
            //   00b871800780         | add                 byte ptr [eax - 0x7ff87f8f], bh
            //   00558b               | add                 byte ptr [ebp - 0x75], dl

        $sequence_42 = { 56 8b4510 8b4d0c 8b5508 befbffffff c600e8 29d6 }
            // n = 7, score = 500
            //   56                   | push                esi
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   befbffffff           | mov                 esi, 0xfffffffb
            //   c600e8               | mov                 byte ptr [eax], 0xe8
            //   29d6                 | sub                 esi, edx

        $sequence_43 = { 8b7020 8b7840 89c3 83c33c }
            // n = 4, score = 300
            //   8b7020               | mov                 esi, dword ptr [eax + 0x20]
            //   8b7840               | mov                 edi, dword ptr [eax + 0x40]
            //   89c3                 | mov                 ebx, eax
            //   83c33c               | add                 ebx, 0x3c

        $sequence_44 = { 89e2 31f6 89720c 897208 }
            // n = 4, score = 200
            //   89e2                 | mov                 edx, esp
            //   31f6                 | xor                 esi, esi
            //   89720c               | mov                 dword ptr [edx + 0xc], esi
            //   897208               | mov                 dword ptr [edx + 8], esi

        $sequence_45 = { e8???????? 48 8d154d1f0000 48 8bcb 48 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   48                   | dec                 eax
            //   8d154d1f0000         | lea                 edx, dword ptr [0x1f4d]
            //   48                   | dec                 eax
            //   8bcb                 | mov                 ecx, ebx
            //   48                   | dec                 eax

        $sequence_46 = { 89442428 48 8d1513240000 45 33c0 48 }
            // n = 6, score = 100
            //   89442428             | mov                 dword ptr [esp + 0x28], eax
            //   48                   | dec                 eax
            //   8d1513240000         | lea                 edx, dword ptr [0x2413]
            //   45                   | inc                 ebp
            //   33c0                 | xor                 eax, eax
            //   48                   | dec                 eax

        $sequence_47 = { 83ec10 f20f1005???????? 0f28c8 8b4c247c 660f6ed1 }
            // n = 5, score = 100
            //   83ec10               | sub                 esp, 0x10
            //   f20f1005????????     |                     
            //   0f28c8               | movaps              xmm1, xmm0
            //   8b4c247c             | mov                 ecx, dword ptr [esp + 0x7c]
            //   660f6ed1             | movd                xmm2, ecx

        $sequence_48 = { 89842480000000 89e8 894c247c 8b8c2480000000 01c8 83c1c0 81f9c00f0000 }
            // n = 7, score = 100
            //   89842480000000       | mov                 dword ptr [esp + 0x80], eax
            //   89e8                 | mov                 eax, ebp
            //   894c247c             | mov                 dword ptr [esp + 0x7c], ecx
            //   8b8c2480000000       | mov                 ecx, dword ptr [esp + 0x80]
            //   01c8                 | add                 eax, ecx
            //   83c1c0               | add                 ecx, -0x40
            //   81f9c00f0000         | cmp                 ecx, 0xfc0

        $sequence_49 = { 52 e8???????? 8db5fcfeffff e8???????? be???????? }
            // n = 5, score = 100
            //   52                   | push                edx
            //   e8????????           |                     
            //   8db5fcfeffff         | lea                 esi, dword ptr [ebp - 0x104]
            //   e8????????           |                     
            //   be????????           |                     

        $sequence_50 = { b8???????? e8???????? 84c0 0f84c1000000 53 56 }
            // n = 6, score = 100
            //   b8????????           |                     
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   0f84c1000000         | je                  0xc7
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_51 = { 8bd3 48 8bce e8???????? 48 8d0d221f0000 }
            // n = 6, score = 100
            //   8bd3                 | mov                 edx, ebx
            //   48                   | dec                 eax
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   48                   | dec                 eax
            //   8d0d221f0000         | lea                 ecx, dword ptr [0x1f22]

        $sequence_52 = { 31d2 890c24 c744240400000000 89442428 89542424 e8???????? 8d0dbe30d800 }
            // n = 7, score = 100
            //   31d2                 | xor                 edx, edx
            //   890c24               | mov                 dword ptr [esp], ecx
            //   c744240400000000     | mov                 dword ptr [esp + 4], 0
            //   89442428             | mov                 dword ptr [esp + 0x28], eax
            //   89542424             | mov                 dword ptr [esp + 0x24], edx
            //   e8????????           |                     
            //   8d0dbe30d800         | lea                 ecx, dword ptr [0xd830be]

        $sequence_53 = { 8d0df3120000 45 33c0 33d2 e8???????? 33c0 }
            // n = 6, score = 100
            //   8d0df3120000         | lea                 ecx, dword ptr [0x12f3]
            //   45                   | inc                 ebp
            //   33c0                 | xor                 eax, eax
            //   33d2                 | xor                 edx, edx
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax

        $sequence_54 = { 8b5f68 899c24bc000000 8b5f64 899c24c0000000 89b424c4000000 }
            // n = 5, score = 100
            //   8b5f68               | mov                 ebx, dword ptr [edi + 0x68]
            //   899c24bc000000       | mov                 dword ptr [esp + 0xbc], ebx
            //   8b5f64               | mov                 ebx, dword ptr [edi + 0x64]
            //   899c24c0000000       | mov                 dword ptr [esp + 0xc0], ebx
            //   89b424c4000000       | mov                 dword ptr [esp + 0xc4], esi

        $sequence_55 = { 890c24 c744240400000000 8954241c e8???????? 8d0dda30d800 890424 }
            // n = 6, score = 100
            //   890c24               | mov                 dword ptr [esp], ecx
            //   c744240400000000     | mov                 dword ptr [esp + 4], 0
            //   8954241c             | mov                 dword ptr [esp + 0x1c], edx
            //   e8????????           |                     
            //   8d0dda30d800         | lea                 ecx, dword ptr [0xd830da]
            //   890424               | mov                 dword ptr [esp], eax

        $sequence_56 = { e8???????? 8d8424b0000000 8b30 8b7804 8b5808 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   8d8424b0000000       | lea                 eax, dword ptr [esp + 0xb0]
            //   8b30                 | mov                 esi, dword ptr [eax]
            //   8b7804               | mov                 edi, dword ptr [eax + 4]
            //   8b5808               | mov                 ebx, dword ptr [eax + 8]

        $sequence_57 = { 03cd e8???????? 48 8d055d150000 44 8d4e02 }
            // n = 6, score = 100
            //   03cd                 | add                 ecx, ebp
            //   e8????????           |                     
            //   48                   | dec                 eax
            //   8d055d150000         | lea                 eax, dword ptr [0x155d]
            //   44                   | inc                 esp
            //   8d4e02               | lea                 ecx, dword ptr [esi + 2]

        $sequence_58 = { 4c 8d05ce3f0000 89442420 ff15???????? 44 03e0 }
            // n = 6, score = 100
            //   4c                   | dec                 esp
            //   8d05ce3f0000         | lea                 eax, dword ptr [0x3fce]
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   ff15????????         |                     
            //   44                   | inc                 esp
            //   03e0                 | add                 esp, eax

    condition:
        7 of them and filesize < 270336
}