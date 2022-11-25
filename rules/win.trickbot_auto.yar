rule win_trickbot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.trickbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.trickbot"
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
        $sequence_0 = { 83e002 83c002 eb0d 2500000080 f7d8 1bc0 83e007 }
            // n = 7, score = 4500
            //   83e002               | and                 eax, 2
            //   83c002               | add                 eax, 2
            //   eb0d                 | jmp                 0xf
            //   2500000080           | and                 eax, 0x80000000
            //   f7d8                 | neg                 eax
            //   1bc0                 | sbb                 eax, eax
            //   83e007               | and                 eax, 7

        $sequence_1 = { 2500000080 f7d8 1bc0 83e020 83c020 eb36 }
            // n = 6, score = 4500
            //   2500000080           | and                 eax, 0x80000000
            //   f7d8                 | neg                 eax
            //   1bc0                 | sbb                 eax, eax
            //   83e020               | and                 eax, 0x20
            //   83c020               | add                 eax, 0x20
            //   eb36                 | jmp                 0x38

        $sequence_2 = { 83c010 eb25 a900000040 7411 2500000080 f7d8 1bc0 }
            // n = 7, score = 4500
            //   83c010               | add                 eax, 0x10
            //   eb25                 | jmp                 0x27
            //   a900000040           | test                eax, 0x40000000
            //   7411                 | je                  0x13
            //   2500000080           | and                 eax, 0x80000000
            //   f7d8                 | neg                 eax
            //   1bc0                 | sbb                 eax, eax

        $sequence_3 = { f7d8 1bc0 83e002 83c002 eb0d }
            // n = 5, score = 4500
            //   f7d8                 | neg                 eax
            //   1bc0                 | sbb                 eax, eax
            //   83e002               | and                 eax, 2
            //   83c002               | add                 eax, 2
            //   eb0d                 | jmp                 0xf

        $sequence_4 = { 2500000080 f7d8 1bc0 83e070 83c010 eb25 a900000040 }
            // n = 7, score = 4500
            //   2500000080           | and                 eax, 0x80000000
            //   f7d8                 | neg                 eax
            //   1bc0                 | sbb                 eax, eax
            //   83e070               | and                 eax, 0x70
            //   83c010               | add                 eax, 0x10
            //   eb25                 | jmp                 0x27
            //   a900000040           | test                eax, 0x40000000

        $sequence_5 = { 83c020 eb36 2500000080 f7d8 }
            // n = 4, score = 4500
            //   83c020               | add                 eax, 0x20
            //   eb36                 | jmp                 0x38
            //   2500000080           | and                 eax, 0x80000000
            //   f7d8                 | neg                 eax

        $sequence_6 = { 8b07 a900000020 7429 a900000040 7411 }
            // n = 5, score = 4300
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   a900000020           | test                eax, 0x20000000
            //   7429                 | je                  0x2b
            //   a900000040           | test                eax, 0x40000000
            //   7411                 | je                  0x13

        $sequence_7 = { c705????????fdffffff c705????????feffffff c705????????ffffffff e8???????? }
            // n = 4, score = 3600
            //   c705????????fdffffff     |     
            //   c705????????feffffff     |     
            //   c705????????ffffffff     |     
            //   e8????????           |                     

        $sequence_8 = { 895df8 895df4 895dec 66c745f00005 }
            // n = 4, score = 3500
            //   895df8               | je                  0x1d
            //   895df4               | and                 eax, 0x80000000
            //   895dec               | je                  0x2b
            //   66c745f00005         | test                eax, 0x40000000

        $sequence_9 = { 50 ff15???????? 8b4604 85c0 7407 50 ff15???????? }
            // n = 7, score = 3400
            //   50                   | dec                 eax
            //   ff15????????         |                     
            //   8b4604               | mov                 eax, dword ptr [ecx + 0x30]
            //   85c0                 | dec                 eax
            //   7407                 | mov                 ecx, dword ptr [ecx + 0x10]
            //   50                   | dec                 eax
            //   ff15????????         |                     

        $sequence_10 = { 33ff 57 6880000000 6a02 57 6a01 68000000c0 }
            // n = 7, score = 3400
            //   33ff                 | mov                 eax, dword ptr [ecx + 0x40]
            //   57                   | dec                 eax
            //   6880000000           | mov                 dword ptr [esp + 0x30], eax
            //   6a02                 | dec                 eax
            //   57                   | mov                 eax, dword ptr [ecx + 0x38]
            //   6a01                 | dec                 eax
            //   68000000c0           | mov                 dword ptr [esp + 0x28], eax

        $sequence_11 = { 8b45fc 8d1489 8d0cd0 8b4114 2b410c }
            // n = 5, score = 3000
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8d1489               | lea                 edx, [ecx + ecx*4]
            //   8d0cd0               | lea                 ecx, [eax + edx*8]
            //   8b4114               | mov                 eax, dword ptr [ecx + 0x14]
            //   2b410c               | sub                 eax, dword ptr [ecx + 0xc]

        $sequence_12 = { 488b5118 4889442440 488b4148 4889442438 }
            // n = 4, score = 2800
            //   488b5118             | dec                 eax
            //   4889442440           | mov                 eax, dword ptr [ecx + 0x48]
            //   488b4148             | dec                 esp
            //   4889442438           | mov                 edx, dword ptr [ecx]

        $sequence_13 = { 488b4148 4c8b11 4c8b4928 4c8b4120 }
            // n = 4, score = 2800
            //   488b4148             | dec                 eax
            //   4c8b11               | mov                 edx, dword ptr [ecx + 0x18]
            //   4c8b4928             | dec                 eax
            //   4c8b4120             | mov                 dword ptr [esp + 0x38], eax

        $sequence_14 = { 4c8b4120 488b5118 4889442438 488b4140 }
            // n = 4, score = 2800
            //   4c8b4120             | dec                 eax
            //   488b5118             | mov                 dword ptr [esp + 0x38], eax
            //   4889442438           | dec                 eax
            //   488b4140             | mov                 eax, dword ptr [ecx + 0x40]

        $sequence_15 = { 4c8b4928 4c8b4120 488b5118 4889442440 }
            // n = 4, score = 2800
            //   4c8b4928             | dec                 eax
            //   4c8b4120             | mov                 dword ptr [esp + 0x30], eax
            //   488b5118             | dec                 eax
            //   4889442440           | mov                 dword ptr [esp + 0x40], eax

        $sequence_16 = { 488b4148 4889442438 488b4140 4889442430 488b4138 4889442428 488b4130 }
            // n = 7, score = 2800
            //   488b4148             | dec                 eax
            //   4889442438           | mov                 eax, dword ptr [ecx + 0x48]
            //   488b4140             | dec                 eax
            //   4889442430           | mov                 dword ptr [esp + 0x38], eax
            //   488b4138             | dec                 eax
            //   4889442428           | mov                 eax, dword ptr [ecx + 0x40]
            //   488b4130             | dec                 eax

        $sequence_17 = { 488b01 488b5118 488b4910 ffd0 }
            // n = 4, score = 2800
            //   488b01               | mov                 eax, dword ptr [ecx + 0x50]
            //   488b5118             | dec                 esp
            //   488b4910             | mov                 edx, dword ptr [ecx]
            //   ffd0                 | dec                 esp

        $sequence_18 = { 488b01 4c8b4120 488b5118 488b4910 }
            // n = 4, score = 2800
            //   488b01               | dec                 eax
            //   4c8b4120             | mov                 eax, dword ptr [ecx + 0x30]
            //   488b5118             | dec                 eax
            //   488b4910             | mov                 ecx, dword ptr [ecx + 0x10]

        $sequence_19 = { 53 6a03 53 6a01 6800010000 }
            // n = 5, score = 2800
            //   53                   | mov                 dword ptr [esp + 0x20], eax
            //   6a03                 | inc                 ecx
            //   53                   | call                edx
            //   6a01                 | dec                 eax
            //   6800010000           | mov                 eax, dword ptr [ecx + 0x38]

        $sequence_20 = { 4889442428 488b4130 488b4910 4889442420 }
            // n = 4, score = 2800
            //   4889442428           | mov                 edx, dword ptr [ecx]
            //   488b4130             | dec                 esp
            //   488b4910             | mov                 ecx, dword ptr [ecx + 0x28]
            //   4889442420           | dec                 esp

        $sequence_21 = { 2bc2 d1e8 03c2 c1e806 6bc05f }
            // n = 5, score = 2000
            //   2bc2                 | mov                 dword ptr [esp + 0x38], eax
            //   d1e8                 | dec                 eax
            //   03c2                 | mov                 eax, dword ptr [ecx + 0x40]
            //   c1e806               | dec                 eax
            //   6bc05f               | mov                 dword ptr [esp + 0x30], eax

        $sequence_22 = { 83780400 7404 8b4008 c3 }
            // n = 4, score = 2000
            //   83780400             | mov                 eax, dword ptr [ecx + 0x48]
            //   7404                 | dec                 eax
            //   8b4008               | mov                 dword ptr [esp + 0x38], eax
            //   c3                   | dec                 eax

        $sequence_23 = { 6820bf0200 68905f0100 68905f0100 50 }
            // n = 4, score = 2000
            //   6820bf0200           | mov                 eax, dword ptr [ecx + 0x30]
            //   68905f0100           | dec                 eax
            //   68905f0100           | mov                 ecx, dword ptr [ecx + 0x10]
            //   50                   | dec                 eax

        $sequence_24 = { 85c0 751b 68e8030000 ff15???????? }
            // n = 4, score = 2000
            //   85c0                 | dec                 esp
            //   751b                 | mov                 eax, dword ptr [ecx + 0x20]
            //   68e8030000           | dec                 eax
            //   ff15????????         |                     

        $sequence_25 = { 51 68e9fd0000 50 e8???????? }
            // n = 4, score = 1800
            //   51                   | dec                 eax
            //   68e9fd0000           | mov                 eax, dword ptr [ecx + 0x38]
            //   50                   | dec                 eax
            //   e8????????           |                     

        $sequence_26 = { e8???????? e8???????? e8???????? 33c9 ff15???????? }
            // n = 5, score = 1500
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   33c9                 | mov                 eax, dword ptr [ecx + 0x40]
            //   ff15????????         |                     

        $sequence_27 = { c3 6a01 ff15???????? 50 }
            // n = 4, score = 1500
            //   c3                   | ret                 
            //   6a01                 | push                1
            //   ff15????????         |                     
            //   50                   | push                eax

        $sequence_28 = { 8bc1 66ad 85c0 741c }
            // n = 4, score = 1300
            //   8bc1                 | and                 eax, 0x80000000
            //   66ad                 | neg                 eax
            //   85c0                 | sbb                 eax, eax
            //   741c                 | add                 eax, 0x20

        $sequence_29 = { 85c0 7f0b e8???????? 8b05???????? }
            // n = 4, score = 1300
            //   85c0                 | mov                 eax, dword ptr [ecx + 0x38]
            //   7f0b                 | dec                 eax
            //   e8????????           |                     
            //   8b05????????         |                     

        $sequence_30 = { 8b01 59 03d0 52 ebdc }
            // n = 5, score = 1300
            //   8b01                 | neg                 eax
            //   59                   | sbb                 eax, eax
            //   03d0                 | and                 eax, 0x70
            //   52                   | add                 eax, 0x10
            //   ebdc                 | add                 eax, 0x20

        $sequence_31 = { e8???????? 83f801 7411 ba0a000000 }
            // n = 4, score = 1300
            //   e8????????           |                     
            //   83f801               | dec                 eax
            //   7411                 | mov                 dword ptr [esp + 0x30], eax
            //   ba0a000000           | dec                 eax

        $sequence_32 = { 50 8b450c ff4d0c ba28000000 }
            // n = 4, score = 1200
            //   50                   | dec                 esp
            //   8b450c               | mov                 eax, dword ptr [ecx + 0x20]
            //   ff4d0c               | dec                 eax
            //   ba28000000           | mov                 edx, dword ptr [ecx + 0x18]

        $sequence_33 = { c1e102 2bc1 8b00 894508 }
            // n = 4, score = 1200
            //   c1e102               | neg                 eax
            //   2bc1                 | sbb                 eax, eax
            //   8b00                 | and                 eax, 0x20
            //   894508               | add                 eax, 0x20

        $sequence_34 = { 85c0 741c 3bc1 7213 2bc1 }
            // n = 5, score = 1200
            //   85c0                 | add                 eax, 0x10
            //   741c                 | jmp                 0x2a
            //   3bc1                 | test                eax, 0x40000000
            //   7213                 | je                  0x1d
            //   2bc1                 | and                 eax, 0x80000000

        $sequence_35 = { 7405 e8???????? ff15???????? 8bc3 }
            // n = 4, score = 1200
            //   7405                 | mov                 ecx, dword ptr [ecx + 0x10]
            //   e8????????           |                     
            //   ff15????????         |                     
            //   8bc3                 | dec                 eax

        $sequence_36 = { 52 ebdc 89450c 8bc5 }
            // n = 4, score = 1200
            //   52                   | and                 eax, 7
            //   ebdc                 | inc                 eax
            //   89450c               | je                  0x13
            //   8bc5                 | and                 eax, 0x80000000

        $sequence_37 = { ff5508 8b5510 8b4a04 ff5508 50 51 50 }
            // n = 7, score = 1100
            //   ff5508               | pop                 ecx
            //   8b5510               | add                 edx, eax
            //   8b4a04               | push                edx
            //   ff5508               | jmp                 0xffffffe1
            //   50                   | mov                 eax, dword ptr [ecx]
            //   51                   | pop                 ecx
            //   50                   | add                 edx, eax

        $sequence_38 = { 2bc1 8b00 3bc7 72f2 }
            // n = 4, score = 1100
            //   2bc1                 | mov                 edx, dword ptr [ecx + 0x18]
            //   8b00                 | dec                 eax
            //   3bc7                 | mov                 dword ptr [esp + 0x40], eax
            //   72f2                 | dec                 eax

        $sequence_39 = { 8b4a04 ff5508 8b5510 8b4a0c }
            // n = 4, score = 1100
            //   8b4a04               | lodsw               ax, word ptr [esi]
            //   ff5508               | test                eax, eax
            //   8b5510               | je                  0x20
            //   8b4a0c               | pop                 ecx

        $sequence_40 = { f7e2 8d9500040000 03d0 895510 }
            // n = 4, score = 1000
            //   f7e2                 | dec                 eax
            //   8d9500040000         | mov                 dword ptr [esp + 0x30], eax
            //   03d0                 | dec                 eax
            //   895510               | mov                 eax, dword ptr [ecx + 0x38]

        $sequence_41 = { ff4d0c ba28000000 f7e2 8d9500040000 }
            // n = 4, score = 1000
            //   ff4d0c               | mov                 eax, dword ptr [ecx + 0x48]
            //   ba28000000           | dec                 eax
            //   f7e2                 | mov                 eax, dword ptr [ecx + 0x48]
            //   8d9500040000         | dec                 esp

        $sequence_42 = { 7c22 3c39 7f1e 0fbec0 }
            // n = 4, score = 900
            //   7c22                 | mov                 edx, dword ptr [ecx]
            //   3c39                 | dec                 esp
            //   7f1e                 | mov                 ecx, dword ptr [ecx + 0x28]
            //   0fbec0               | dec                 esp

        $sequence_43 = { ff15???????? 8bf0 c1ee1f 83f601 }
            // n = 4, score = 900
            //   ff15????????         |                     
            //   8bf0                 | dec                 eax
            //   c1ee1f               | mov                 dword ptr [esp + 0x38], eax
            //   83f601               | dec                 eax

        $sequence_44 = { 85c9 7514 398e8c000000 750c }
            // n = 4, score = 900
            //   85c9                 | mov                 dword ptr [esp + 0x38], eax
            //   7514                 | dec                 eax
            //   398e8c000000         | mov                 eax, dword ptr [ecx + 0x40]
            //   750c                 | dec                 eax

        $sequence_45 = { 8bcf e8???????? 8bf0 85ed }
            // n = 4, score = 900
            //   8bcf                 | mov                 dword ptr [esp + 0x40], eax
            //   e8????????           |                     
            //   8bf0                 | dec                 eax
            //   85ed                 | mov                 eax, dword ptr [ecx + 0x48]

        $sequence_46 = { 58 41 41 41 }
            // n = 4, score = 900
            //   58                   | mov                 dword ptr [esp + 0x30], eax
            //   41                   | dec                 eax
            //   41                   | mov                 eax, dword ptr [ecx + 0x38]
            //   41                   | dec                 esp

        $sequence_47 = { 3bd1 0f8293000000 038e8c000000 3bd1 0f8385000000 }
            // n = 5, score = 900
            //   3bd1                 | mov                 dword ptr [esp + 0x38], eax
            //   0f8293000000         | dec                 eax
            //   038e8c000000         | mov                 eax, dword ptr [ecx + 0x40]
            //   3bd1                 | dec                 eax
            //   0f8385000000         | mov                 dword ptr [esp + 0x30], eax

        $sequence_48 = { 7909 8bc8 e8???????? eb28 }
            // n = 4, score = 900
            //   7909                 | dec                 esp
            //   8bc8                 | mov                 ecx, dword ptr [ecx + 0x28]
            //   e8????????           |                     
            //   eb28                 | dec                 esp

        $sequence_49 = { ff15???????? 85c0 0f89d2000000 8bc8 e8???????? bb17000000 }
            // n = 6, score = 900
            //   ff15????????         |                     
            //   85c0                 | mov                 eax, dword ptr [ecx + 0x20]
            //   0f89d2000000         | dec                 eax
            //   8bc8                 | mov                 edx, dword ptr [ecx + 0x18]
            //   e8????????           |                     
            //   bb17000000           | dec                 eax

        $sequence_50 = { 8b03 0fbae01d 732b 0fbae01e 7315 0fbae01f }
            // n = 6, score = 900
            //   8b03                 | dec                 eax
            //   0fbae01d             | mov                 eax, dword ptr [ecx + 0x40]
            //   732b                 | dec                 eax
            //   0fbae01e             | mov                 dword ptr [esp + 0x30], eax
            //   7315                 | dec                 esp
            //   0fbae01f             | mov                 eax, dword ptr [ecx + 0x20]

        $sequence_51 = { 7911 8bc8 e8???????? bb10000000 e9???????? }
            // n = 5, score = 900
            //   7911                 | dec                 esp
            //   8bc8                 | mov                 ecx, dword ptr [ecx + 0x28]
            //   e8????????           |                     
            //   bb10000000           | dec                 esp
            //   e9????????           |                     

        $sequence_52 = { e8???????? e8???????? 8bd8 85c0 740f }
            // n = 5, score = 900
            //   e8????????           |                     
            //   e8????????           |                     
            //   8bd8                 | dec                 eax
            //   85c0                 | mov                 edx, dword ptr [ecx + 0x18]
            //   740f                 | dec                 eax

        $sequence_53 = { 8bc8 33c0 85c9 0f95c0 eb02 33c0 }
            // n = 6, score = 800
            //   8bc8                 | mov                 eax, dword ptr [ecx + 0x40]
            //   33c0                 | dec                 eax
            //   85c9                 | mov                 dword ptr [esp + 0x30], eax
            //   0f95c0               | dec                 eax
            //   eb02                 | mov                 dword ptr [esp + 0x40], eax
            //   33c0                 | dec                 eax

        $sequence_54 = { 41 41 50 2bc1 8b00 }
            // n = 5, score = 800
            //   41                   | mov                 eax, dword ptr [ecx + 0x38]
            //   41                   | dec                 eax
            //   50                   | mov                 dword ptr [esp + 0x28], eax
            //   2bc1                 | dec                 esp
            //   8b00                 | mov                 edx, dword ptr [ecx]

        $sequence_55 = { 8bf7 8bd7 fc 8bc1 66ad }
            // n = 5, score = 700
            //   8bf7                 | test                eax, 0x40000000
            //   8bd7                 | je                  0x18
            //   fc                   | and                 eax, 0x80000000
            //   8bc1                 | neg                 eax
            //   66ad                 | sbb                 eax, eax

        $sequence_56 = { c1e002 03c8 8b01 59 }
            // n = 4, score = 700
            //   c1e002               | and                 eax, 0x80000000
            //   03c8                 | neg                 eax
            //   8b01                 | test                eax, 0x20000000
            //   59                   | je                  0x2b

        $sequence_57 = { 59 50 e2fd 8bc7 }
            // n = 4, score = 700
            //   59                   | jmp                 0x27
            //   50                   | test                eax, 0x40000000
            //   e2fd                 | je                  0x18
            //   8bc7                 | and                 eax, 0x80000000

        $sequence_58 = { 8dbf00500310 8bd6 897d08 3bc8 }
            // n = 4, score = 200
            //   8dbf00500310         | dec                 eax
            //   8bd6                 | mov                 eax, dword ptr [ecx + 0x38]
            //   897d08               | dec                 eax
            //   3bc8                 | mov                 dword ptr [esp + 0x28], eax

        $sequence_59 = { 8b7d10 2bf9 53 50 }
            // n = 4, score = 200
            //   8b7d10               | mov                 eax, dword ptr [ecx + 0x38]
            //   2bf9                 | dec                 eax
            //   53                   | mov                 dword ptr [esp + 0x30], eax
            //   50                   | dec                 eax

        $sequence_60 = { 6a00 6a00 ff15???????? 6a00 6a00 6a00 8d45dc }
            // n = 7, score = 200
            //   6a00                 | mov                 dword ptr [esp + 0x28], eax
            //   6a00                 | dec                 eax
            //   ff15????????         |                     
            //   6a00                 | mov                 eax, dword ptr [ecx + 0x30]
            //   6a00                 | dec                 eax
            //   6a00                 | mov                 edx, dword ptr [ecx + 0x18]
            //   8d45dc               | dec                 eax

        $sequence_61 = { 8bc7 e8???????? 50 e8???????? 83c40c 8bf3 8bc7 }
            // n = 7, score = 100
            //   8bc7                 | neg                 eax
            //   e8????????           |                     
            //   50                   | sbb                 eax, eax
            //   e8????????           |                     
            //   83c40c               | and                 eax, 2
            //   8bf3                 | add                 eax, 2
            //   8bc7                 | jmp                 0x12

        $sequence_62 = { 8b45d4 83c001 8945d4 8b4dfc 51 8b55d4 52 }
            // n = 7, score = 100
            //   8b45d4               | dec                 eax
            //   83c001               | mov                 edx, dword ptr [ecx + 0x18]
            //   8945d4               | dec                 eax
            //   8b4dfc               | mov                 dword ptr [esp + 0x40], eax
            //   51                   | dec                 eax
            //   8b55d4               | mov                 eax, dword ptr [ecx + 0x48]
            //   52                   | dec                 eax

        $sequence_63 = { ff15???????? 6a00 6a00 ff15???????? ff25???????? b8b979379e }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   6a00                 | and                 eax, 2
            //   6a00                 | add                 eax, 2
            //   ff15????????         |                     
            //   ff25????????         |                     
            //   b8b979379e           | jmp                 0x12

        $sequence_64 = { c6864b01000043 c74668d8f40001 6a0d e8???????? 59 }
            // n = 5, score = 100
            //   c6864b01000043       | and                 eax, 0x80000000
            //   c74668d8f40001       | neg                 eax
            //   6a0d                 | sbb                 eax, eax
            //   e8????????           |                     
            //   59                   | and                 eax, 0x70

        $sequence_65 = { ff15???????? ebd5 8365f800 8365d000 c745d400000400 }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   ebd5                 | dec                 esp
            //   8365f800             | mov                 ecx, dword ptr [ecx + 0x28]
            //   8365d000             | dec                 esp
            //   c745d400000400       | mov                 eax, dword ptr [ecx + 0x20]

        $sequence_66 = { ac 7df2 140c 46 83f615 55 0db9e64e93 }
            // n = 7, score = 100
            //   ac                   | and                 eax, 0x80000000
            //   7df2                 | neg                 eax
            //   140c                 | and                 eax, 0x70
            //   46                   | add                 eax, 0x10
            //   83f615               | jmp                 0x2a
            //   55                   | test                eax, 0x40000000
            //   0db9e64e93           | je                  0x1d

        $sequence_67 = { 7502 eb0c 8d55dc 52 ff15???????? ebcc c745f800000000 }
            // n = 7, score = 100
            //   7502                 | dec                 eax
            //   eb0c                 | mov                 edx, dword ptr [ecx + 0x18]
            //   8d55dc               | dec                 eax
            //   52                   | mov                 dword ptr [esp + 0x38], eax
            //   ff15????????         |                     
            //   ebcc                 | dec                 eax
            //   c745f800000000       | mov                 eax, dword ptr [ecx + 0x40]

        $sequence_68 = { 8d4310 8d890cf90001 5a 668b31 }
            // n = 4, score = 100
            //   8d4310               | and                 eax, 0x80000000
            //   8d890cf90001         | neg                 eax
            //   5a                   | and                 eax, 0x70
            //   668b31               | add                 eax, 0x10

        $sequence_69 = { 7502 eb0c 8d45dc 50 ff15???????? }
            // n = 5, score = 100
            //   7502                 | dec                 eax
            //   eb0c                 | mov                 dword ptr [esp + 0x28], eax
            //   8d45dc               | dec                 eax
            //   50                   | mov                 eax, dword ptr [ecx + 0x30]
            //   ff15????????         |                     

        $sequence_70 = { e8???????? 5b 84c0 741d 56 68???????? 8bc7 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   5b                   | jmp                 0x2a
            //   84c0                 | test                eax, 0x40000000
            //   741d                 | je                  0x1d
            //   56                   | add                 eax, 0x20
            //   68????????           |                     
            //   8bc7                 | jmp                 0x38

        $sequence_71 = { 40 8945d0 ff75fc ff75d0 e8???????? 8b45d0 48 }
            // n = 7, score = 100
            //   40                   | dec                 eax
            //   8945d0               | mov                 edx, dword ptr [ecx + 0x18]
            //   ff75fc               | dec                 eax
            //   ff75d0               | mov                 dword ptr [esp + 0x38], eax
            //   e8????????           |                     
            //   8b45d0               | dec                 eax
            //   48                   | mov                 dword ptr [esp + 0x38], eax

        $sequence_72 = { ff15???????? ebcc c745f800000000 c745d400000000 c745d000500000 817dd000100000 760b }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   ebcc                 | mov                 ecx, dword ptr [ecx + 0x28]
            //   c745f800000000       | dec                 esp
            //   c745d400000000       | mov                 eax, dword ptr [ecx + 0x20]
            //   c745d000500000       | dec                 esp
            //   817dd000100000       | mov                 eax, dword ptr [ecx + 0x20]
            //   760b                 | dec                 eax

        $sequence_73 = { 40 50 ff75d4 ff75f8 ff15???????? }
            // n = 5, score = 100
            //   40                   | dec                 eax
            //   50                   | mov                 dword ptr [esp + 0x20], eax
            //   ff75d4               | dec                 eax
            //   ff75f8               | mov                 eax, dword ptr [ecx + 0x40]
            //   ff15????????         |                     

        $sequence_74 = { 85c0 7420 8b4de0 83c101 }
            // n = 4, score = 100
            //   85c0                 | mov                 eax, dword ptr [ecx + 0x50]
            //   7420                 | dec                 esp
            //   8b4de0               | mov                 edx, dword ptr [ecx]
            //   83c101               | dec                 esp

        $sequence_75 = { 06 e8???????? 819755e3464f2d05eb7c 7fc9 2cde c9 b28c }
            // n = 7, score = 100
            //   06                   | and                 eax, 0x80000000
            //   e8????????           |                     
            //   819755e3464f2d05eb7c     | neg    eax
            //   7fc9                 | sbb                 eax, eax
            //   2cde                 | and                 eax, 7
            //   c9                   | and                 eax, 2
            //   b28c                 | add                 eax, 2

        $sequence_76 = { 2bc3 50 8bc7 e8???????? 03c6 03c3 }
            // n = 6, score = 100
            //   2bc3                 | add                 eax, 0x10
            //   50                   | and                 eax, 2
            //   8bc7                 | add                 eax, 2
            //   e8????????           |                     
            //   03c6                 | jmp                 0x12
            //   03c3                 | and                 eax, 0x80000000

        $sequence_77 = { 8365d000 c745d400000400 8b45d0 8945d8 837dd840 7709 }
            // n = 6, score = 100
            //   8365d000             | dec                 eax
            //   c745d400000400       | mov                 dword ptr [esp + 0x30], eax
            //   8b45d0               | dec                 eax
            //   8945d8               | mov                 eax, dword ptr [ecx + 0x38]
            //   837dd840             | dec                 eax
            //   7709                 | mov                 dword ptr [esp + 0x28], eax

    condition:
        7 of them and filesize < 712704
}