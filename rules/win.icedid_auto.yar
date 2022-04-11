rule win_icedid_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.icedid."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.icedid"
        malpedia_rule_date = "20220405"
        malpedia_hash = "ecd38294bd47d5589be5cd5490dc8bb4804afc2a"
        malpedia_version = ""
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
        $sequence_0 = { ff15???????? 50 ff15???????? 8bf7 8bc6 eb02 }
            // n = 6, score = 1300
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8bf7                 | mov                 esi, edi
            //   8bc6                 | mov                 eax, esi
            //   eb02                 | jmp                 4

        $sequence_1 = { 742c 803e00 7427 6a3b 56 ff15???????? }
            // n = 6, score = 1300
            //   742c                 | je                  0x2e
            //   803e00               | cmp                 byte ptr [esi], 0
            //   7427                 | je                  0x29
            //   6a3b                 | push                0x3b
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_2 = { 7411 40 50 6a08 ff15???????? }
            // n = 5, score = 1300
            //   7411                 | je                  0x13
            //   40                   | inc                 eax
            //   50                   | push                eax
            //   6a08                 | push                8
            //   ff15????????         |                     

        $sequence_3 = { ff15???????? 85c0 7420 837c241000 7419 }
            // n = 5, score = 1300
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7420                 | je                  0x22
            //   837c241000           | cmp                 dword ptr [esp + 0x10], 0
            //   7419                 | je                  0x1b

        $sequence_4 = { 50 6801000080 ff15???????? eb13 }
            // n = 4, score = 1300
            //   50                   | push                eax
            //   6801000080           | push                0x80000001
            //   ff15????????         |                     
            //   eb13                 | jmp                 0x15

        $sequence_5 = { f7d0 d1c8 2d20010000 d1c0 f7d0 2d01910000 }
            // n = 6, score = 1300
            //   f7d0                 | not                 eax
            //   d1c8                 | ror                 eax, 1
            //   2d20010000           | sub                 eax, 0x120
            //   d1c0                 | rol                 eax, 1
            //   f7d0                 | not                 eax
            //   2d01910000           | sub                 eax, 0x9101

        $sequence_6 = { be01000080 50 56 ff15???????? }
            // n = 4, score = 1300
            //   be01000080           | mov                 esi, 0x80000001
            //   50                   | push                eax
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_7 = { eb0f 6a08 ff15???????? 50 ff15???????? 8906 }
            // n = 6, score = 1300
            //   eb0f                 | jmp                 0x11
            //   6a08                 | push                8
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8906                 | mov                 dword ptr [esi], eax

        $sequence_8 = { 7511 56 57 ff15???????? 50 }
            // n = 5, score = 1300
            //   7511                 | jne                 0x13
            //   56                   | push                esi
            //   57                   | push                edi
            //   ff15????????         |                     
            //   50                   | push                eax

        $sequence_9 = { c1c90d 0fbec0 03c8 46 8a06 84c0 75f1 }
            // n = 7, score = 1200
            //   c1c90d               | ror                 ecx, 0xd
            //   0fbec0               | movsx               eax, al
            //   03c8                 | add                 ecx, eax
            //   46                   | inc                 esi
            //   8a06                 | mov                 al, byte ptr [esi]
            //   84c0                 | test                al, al
            //   75f1                 | jne                 0xfffffff3

        $sequence_10 = { e8???????? 8bf0 8d45fc 50 ff75fc 6a05 }
            // n = 6, score = 1000
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   8d45fc               | lea                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   6a05                 | push                5

        $sequence_11 = { 8be5 5d c3 8b542404 33c9 }
            // n = 5, score = 1000
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b542404             | mov                 edx, dword ptr [esp + 4]
            //   33c9                 | xor                 ecx, ecx

        $sequence_12 = { 8d4508 50 0fb6440b34 50 }
            // n = 4, score = 800
            //   8d4508               | lea                 eax, dword ptr [ebp + 8]
            //   50                   | push                eax
            //   0fb6440b34           | movzx               eax, byte ptr [ebx + ecx + 0x34]
            //   50                   | push                eax

        $sequence_13 = { 51 51 8b4c240c 53 55 }
            // n = 5, score = 800
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   8b4c240c             | mov                 ecx, dword ptr [esp + 0xc]
            //   53                   | push                ebx
            //   55                   | push                ebp

        $sequence_14 = { 89542414 8b12 85d2 7454 }
            // n = 4, score = 800
            //   89542414             | mov                 dword ptr [esp + 0x14], edx
            //   8b12                 | mov                 edx, dword ptr [edx]
            //   85d2                 | test                edx, edx
            //   7454                 | je                  0x56

        $sequence_15 = { eb5c 8d5004 89542414 8b12 }
            // n = 4, score = 800
            //   eb5c                 | jmp                 0x5e
            //   8d5004               | lea                 edx, dword ptr [eax + 4]
            //   89542414             | mov                 dword ptr [esp + 0x14], edx
            //   8b12                 | mov                 edx, dword ptr [edx]

        $sequence_16 = { 8a4173 a808 75f5 a804 7406 }
            // n = 5, score = 400
            //   8a4173               | mov                 al, byte ptr [ecx + 0x73]
            //   a808                 | test                al, 8
            //   75f5                 | jne                 0xfffffff7
            //   a804                 | test                al, 4
            //   7406                 | je                  8

        $sequence_17 = { ff15???????? 85c0 750a b8010000c0 e9???????? }
            // n = 5, score = 400
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   750a                 | jne                 0xc
            //   b8010000c0           | mov                 eax, 0xc0000001
            //   e9????????           |                     

        $sequence_18 = { ff5010 85c0 7407 33c0 }
            // n = 4, score = 400
            //   ff5010               | call                dword ptr [eax + 0x10]
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   33c0                 | xor                 eax, eax

        $sequence_19 = { 44 8d4904 ff15???????? 33ff }
            // n = 4, score = 300
            //   44                   | inc                 esp
            //   8d4904               | lea                 ecx, dword ptr [ecx + 4]
            //   ff15????????         |                     
            //   33ff                 | xor                 edi, edi

        $sequence_20 = { c7854005000047657450 c78544050000726f6365 c7854805000073734865 66c7854c0500006170 }
            // n = 4, score = 300
            //   c7854005000047657450     | test    eax, eax
            //   c78544050000726f6365     | je    0x14
            //   c7854805000073734865     | mov    eax, dword ptr [ebp + 0x50]
            //   66c7854c0500006170     | test    eax, eax

        $sequence_21 = { 85c0 7412 8b4550 85c0 740b }
            // n = 5, score = 300
            //   85c0                 | not                 eax
            //   7412                 | ror                 eax, 1
            //   8b4550               | sub                 eax, 0x120
            //   85c0                 | rol                 eax, 1
            //   740b                 | not                 eax

        $sequence_22 = { ff15???????? 85c0 7473 8b4550 }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   85c0                 | je                  0x13
            //   7473                 | inc                 eax
            //   8b4550               | push                eax

        $sequence_23 = { c7853401000050726f63 c7853801000065737300 c785300300006b65726e c78534030000656c3332 }
            // n = 4, score = 300
            //   c7853401000050726f63     | push    8
            //   c7853801000065737300     | push    0
            //   c785300300006b65726e     | xor    eax, eax
            //   c78534030000656c3332     | inc    eax

        $sequence_24 = { c7859001000056697274 c7859401000075616c46 c7859801000072656500 c785b00400006b65726e }
            // n = 4, score = 300
            //   c7859001000056697274     | not    eax
            //   c7859401000075616c46     | ror    eax, 1
            //   c7859801000072656500     | sub    eax, 0x120
            //   c785b00400006b65726e     | rol    eax, 1

        $sequence_25 = { 0f94c7 8bc7 eb02 33c0 48 }
            // n = 5, score = 300
            //   0f94c7               | sete                bh
            //   8bc7                 | mov                 eax, edi
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   48                   | dec                 eax

        $sequence_26 = { c785a807000053747243 c785ac07000068724100 c7858001000053686c77 c785840100006170692e c78588010000646c6c00 e8???????? }
            // n = 6, score = 300
            //   c785a807000053747243     | je    0x14
            //   c785ac07000068724100     | mov    dword ptr [ebp + 0x190], 0x74726956
            //   c7858001000053686c77     | mov    dword ptr [ebp + 0x194], 0x466c6175
            //   c785840100006170692e     | mov    dword ptr [ebp + 0x198], 0x656572
            //   c78588010000646c6c00     | mov    dword ptr [ebp + 0x4b0], 0x6e72656b
            //   e8????????           |                     

        $sequence_27 = { 7414 ff15???????? 4c 8bc3 33d2 48 8bc8 }
            // n = 7, score = 300
            //   7414                 | je                  0x16
            //   ff15????????         |                     
            //   4c                   | dec                 esp
            //   8bc3                 | mov                 eax, ebx
            //   33d2                 | xor                 edx, edx
            //   48                   | dec                 eax
            //   8bc8                 | mov                 ecx, eax

        $sequence_28 = { 48 85ff 7414 ff15???????? 4c 8bc7 33d2 }
            // n = 7, score = 300
            //   48                   | dec                 eax
            //   85ff                 | test                edi, edi
            //   7414                 | je                  0x16
            //   ff15????????         |                     
            //   4c                   | dec                 esp
            //   8bc7                 | mov                 eax, edi
            //   33d2                 | xor                 edx, edx

        $sequence_29 = { c785e404000070656e4b c785e804000065794578 66c785ec0400004100 c785900400006b65726e c78594040000656c3332 }
            // n = 5, score = 300
            //   c785e404000070656e4b     | push    eax
            //   c785e804000065794578     | mov    esi, edi
            //   66c785ec0400004100     | mov    eax, esi
            //   c785900400006b65726e     | jmp    8
            //   c78594040000656c3332     | test    eax, eax

        $sequence_30 = { c785e805000065727300 c785f000000057696e68 c785f40000007474702e c785f8000000646c6c00 e8???????? 660f6f05???????? }
            // n = 6, score = 300
            //   c785e805000065727300     | jne    0x13
            //   c785f000000057696e68     | push    esi
            //   c785f40000007474702e     | push    edi
            //   c785f8000000646c6c00     | test    eax, eax
            //   e8????????           |                     
            //   660f6f05????????     |                     

        $sequence_31 = { 33c0 4c 8d9c24a0000000 49 8b5b20 49 }
            // n = 6, score = 300
            //   33c0                 | xor                 eax, eax
            //   4c                   | dec                 esp
            //   8d9c24a0000000       | lea                 ebx, dword ptr [esp + 0xa0]
            //   49                   | dec                 ecx
            //   8b5b20               | mov                 ebx, dword ptr [ebx + 0x20]
            //   49                   | dec                 ecx

        $sequence_32 = { 837a1000 488bf1 0f8499000000 8b5a10 4803d9 837b0c00 0f8489000000 }
            // n = 7, score = 100
            //   837a1000             | xor                 eax, eax
            //   488bf1               | cmp                 dword ptr [edx + 0x10], 0
            //   0f8499000000         | dec                 eax
            //   8b5a10               | mov                 esi, ecx
            //   4803d9               | je                  0x9f
            //   837b0c00             | mov                 ebx, dword ptr [edx + 0x10]
            //   0f8489000000         | dec                 eax

        $sequence_33 = { 33d2 488bc8 ff15???????? 488bb590020000 4885f6 7414 }
            // n = 6, score = 100
            //   33d2                 | dec                 eax
            //   488bc8               | lea                 edx, dword ptr [ebp + 0x290]
            //   ff15????????         |                     
            //   488bb590020000       | dec                 eax
            //   4885f6               | lea                 ecx, dword ptr [ebp + 0x56]
            //   7414                 | test                eax, eax

        $sequence_34 = { 4c8b742420 eba1 488bb590020000 488b7c2438 }
            // n = 4, score = 100
            //   4c8b742420           | jne                 0xd
            //   eba1                 | xor                 edx, edx
            //   488bb590020000       | dec                 eax
            //   488b7c2438           | mov                 ecx, eax

        $sequence_35 = { 4883c314 e9???????? ff15???????? 33c0 }
            // n = 4, score = 100
            //   4883c314             | dec                 eax
            //   e9????????           |                     
            //   ff15????????         |                     
            //   33c0                 | add                 ebx, 0x14

        $sequence_36 = { ff15???????? 80bb8000000040 0f8577ffffff 488d8b81000000 488d542450 e8???????? }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   80bb8000000040       | jmp                 0xffffffa8
            //   0f8577ffffff         | dec                 eax
            //   488d8b81000000       | mov                 esi, dword ptr [ebp + 0x290]
            //   488d542450           | dec                 eax
            //   e8????????           |                     

        $sequence_37 = { 4c8d8598020000 488d9590020000 488d4d56 e8???????? 85c0 750b ff15???????? }
            // n = 7, score = 100
            //   4c8d8598020000       | add                 ebx, ecx
            //   488d9590020000       | cmp                 dword ptr [ebx + 0xc], 0
            //   488d4d56             | je                  0x8f
            //   e8????????           |                     
            //   85c0                 | dec                 esp
            //   750b                 | lea                 eax, dword ptr [ebp + 0x298]
            //   ff15????????         |                     

        $sequence_38 = { 8364242000 4533c9 33d2 33c9 ff15???????? eb0b }
            // n = 6, score = 100
            //   8364242000           | jmp                 0xffffffa3
            //   4533c9               | dec                 eax
            //   33d2                 | mov                 esi, dword ptr [ebp + 0x290]
            //   33c9                 | dec                 eax
            //   ff15????????         |                     
            //   eb0b                 | mov                 edi, dword ptr [esp + 0x38]

        $sequence_39 = { ff15???????? 488d5702 488bce ff15???????? ba22000000 }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   488d5702             | mov                 edi, dword ptr [esp + 0x38]
            //   488bce               | dec                 esp
            //   ff15????????         |                     
            //   ba22000000           | mov                 esi, dword ptr [esp + 0x20]

    condition:
        7 of them and filesize < 303104
}