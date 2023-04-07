rule win_winnti_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.winnti."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.winnti"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
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
        $sequence_0 = { e8???????? 83c404 8945cc 8bd0 8955dc 33c0 8945d0 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax
            //   8bd0                 | mov                 edx, eax
            //   8955dc               | mov                 dword ptr [ebp - 0x24], edx
            //   33c0                 | xor                 eax, eax
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax

        $sequence_1 = { 6aff 50 6a00 6a00 ffd3 8b54241c }
            // n = 6, score = 200
            //   6aff                 | push                -1
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ffd3                 | call                ebx
            //   8b54241c             | mov                 edx, dword ptr [esp + 0x1c]

        $sequence_2 = { 25ffff0000 3d10a00000 0f8ff4010000 0f84e2010000 }
            // n = 4, score = 200
            //   25ffff0000           | and                 eax, 0xffff
            //   3d10a00000           | cmp                 eax, 0xa010
            //   0f8ff4010000         | jg                  0x1fa
            //   0f84e2010000         | je                  0x1e8

        $sequence_3 = { a1???????? 5f 5e 85c0 744e a1???????? }
            // n = 6, score = 200
            //   a1????????           |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   85c0                 | test                eax, eax
            //   744e                 | je                  0x50
            //   a1????????           |                     

        $sequence_4 = { 803800 7451 bf???????? 83c9ff 33c0 f2ae }
            // n = 6, score = 200
            //   803800               | cmp                 byte ptr [eax], 0
            //   7451                 | je                  0x53
            //   bf????????           |                     
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]

        $sequence_5 = { 83c9ff 33c0 f2ae f7d1 49 807c31ff0d }
            // n = 6, score = 200
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx
            //   807c31ff0d           | cmp                 byte ptr [ecx + esi - 1], 0xd

        $sequence_6 = { f3a4 807c14135c 740a c64414145c c644141500 8db304010000 }
            // n = 6, score = 200
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   807c14135c           | cmp                 byte ptr [esp + edx + 0x13], 0x5c
            //   740a                 | je                  0xc
            //   c64414145c           | mov                 byte ptr [esp + edx + 0x14], 0x5c
            //   c644141500           | mov                 byte ptr [esp + edx + 0x15], 0
            //   8db304010000         | lea                 esi, [ebx + 0x104]

        $sequence_7 = { 894c2428 7ca2 663bc6 0f8f65ffffff eb4f }
            // n = 5, score = 200
            //   894c2428             | mov                 dword ptr [esp + 0x28], ecx
            //   7ca2                 | jl                  0xffffffa4
            //   663bc6               | cmp                 ax, si
            //   0f8f65ffffff         | jg                  0xffffff6b
            //   eb4f                 | jmp                 0x51

        $sequence_8 = { 48c745e700100000 ff15???????? 85c0 742d 48895c2438 }
            // n = 5, score = 100
            //   48c745e700100000     | mov                 edx, ebx
            //   ff15????????         |                     
            //   85c0                 | dec                 eax
            //   742d                 | lea                 ecx, [ebx + eax]
            //   48895c2438           | dec                 esp

        $sequence_9 = { 4883ec30 48c7442420feffffff 48895c2450 4889742458 488bd9 488d0591350100 488901 }
            // n = 7, score = 100
            //   4883ec30             | mov                 eax, dword ptr [ecx + eax*8]
            //   48c7442420feffffff     | inc    ecx
            //   48895c2450           | test                byte ptr [edi + eax + 8], 0x40
            //   4889742458           | je                  0x1e
            //   488bd9               | dec                 eax
            //   488d0591350100       | mov                 ecx, dword ptr [ebp - 0x40]
            //   488901               | dec                 eax

        $sequence_10 = { be20000000 4183fa01 0f8793000000 418bd3 }
            // n = 4, score = 100
            //   be20000000           | inc                 esp
            //   4183fa01             | sub                 cl, cl
            //   0f8793000000         | inc                 ecx
            //   418bd3               | add                 cl, 0x30

        $sequence_11 = { 488b4dc0 48894de8 488d055c690100 488d150dd00100 }
            // n = 4, score = 100
            //   488b4dc0             | je                  0x31
            //   48894de8             | dec                 eax
            //   488d055c690100       | mov                 dword ptr [esp + 0x38], ebx
            //   488d150dd00100       | test                edx, edx

        $sequence_12 = { 4d396e38 0f85cefbffff 488d5610 4983c9ff }
            // n = 4, score = 100
            //   4d396e38             | jle                 0x11
            //   0f85cefbffff         | inc                 ebp
            //   488d5610             | lea                 ebx, [ecx + 1]
            //   4983c9ff             | inc                 ebp

        $sequence_13 = { 85d2 7441 4c89742440 4c89742438 }
            // n = 4, score = 100
            //   85d2                 | test                edx, edx
            //   7441                 | je                  0x43
            //   4c89742440           | dec                 esp
            //   4c89742438           | mov                 dword ptr [esp + 0x40], esi

        $sequence_14 = { e9???????? 488b442450 488d0dab920a00 488b04c1 41f644070840 740b }
            // n = 6, score = 100
            //   e9????????           |                     
            //   488b442450           | movzx               eax, dh
            //   488d0dab920a00       | cmp                 cl, 3
            //   488b04c1             | dec                 eax
            //   41f644070840         | mov                 dword ptr [ebp - 0x19], 0x1000
            //   740b                 | test                eax, eax

        $sequence_15 = { 7405 e8???????? 4883632800 488d0569360100 488903 }
            // n = 5, score = 100
            //   7405                 | mov                 eax, dword ptr [esp + 0x50]
            //   e8????????           |                     
            //   4883632800           | dec                 eax
            //   488d0569360100       | lea                 ecx, [0xa92ab]
            //   488903               | dec                 eax

        $sequence_16 = { eb20 0fb6c3 8d4b60 440fb69c1000410000 400fb6d7 400fb6c6 80f903 }
            // n = 7, score = 100
            //   eb20                 | dec                 eax
            //   0fb6c3               | lea                 edx, [0x173b]
            //   8d4b60               | mov                 esi, 0x20
            //   440fb69c1000410000     | inc    ecx
            //   400fb6d7             | cmp                 edx, 1
            //   400fb6c6             | ja                  0x9d
            //   80f903               | inc                 ecx

        $sequence_17 = { 488b88c0000000 488d059b980a00 395914 4a8b0ce0 }
            // n = 4, score = 100
            //   488b88c0000000       | cmp                 edx, ebx
            //   488d059b980a00       | jae                 0xffffffbc
            //   395914               | xor                 eax, eax
            //   4a8b0ce0             | and                 ecx, 3

        $sequence_18 = { 85c0 0f8459050000 8bc0 488d153b170000 }
            // n = 4, score = 100
            //   85c0                 | dec                 ecx
            //   0f8459050000         | inc                 ecx
            //   8bc0                 | lea                 ecx, [eax + edx]
            //   488d153b170000       | add                 cl, cl

        $sequence_19 = { 8d0c10 02c9 442ac9 4180c130 49ffca }
            // n = 5, score = 100
            //   8d0c10               | or                  byte ptr [eax], 2
            //   02c9                 | inc                 ecx
            //   442ac9               | movzx               eax, byte ptr [eax]
            //   4180c130             | inc                 ecx
            //   49ffca               | inc                 dl

        $sequence_20 = { 41803967 0f44f1 41800802 410fb600 41fec2 49ffc1 }
            // n = 6, score = 100
            //   41803967             | dec                 esp
            //   0f44f1               | mov                 dword ptr [esp + 0x38], esi
            //   41800802             | inc                 ecx
            //   410fb600             | cmp                 byte ptr [ecx], 0x67
            //   41fec2               | cmove               esi, ecx
            //   49ffc1               | inc                 ecx

        $sequence_21 = { 488d0c03 4c011c0a eb10 418b10 25ff0f0000 }
            // n = 5, score = 100
            //   488d0c03             | dec                 ecx
            //   4c011c0a             | dec                 edx
            //   eb10                 | test                eax, eax
            //   418b10               | je                  0x55f
            //   25ff0f0000           | mov                 eax, eax

        $sequence_22 = { 48c1e105 488b04d0 4489540818 458bda 498b8e80000000 4a8b04c1 }
            // n = 6, score = 100
            //   48c1e105             | mov                 dword ptr [ebp - 0x18], ecx
            //   488b04d0             | dec                 eax
            //   4489540818           | lea                 eax, [0x1695c]
            //   458bda               | dec                 eax
            //   498b8e80000000       | lea                 edx, [0x1d00d]
            //   4a8b04c1             | dec                 ebp

        $sequence_23 = { 4585e4 7405 41ffcc eb03 4533e4 41c1fc10 8d6fff }
            // n = 7, score = 100
            //   4585e4               | push                eax
            //   7405                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   41ffcc               | lea                 ecx, [esp + 0x3c]
            //   eb03                 | lea                 edx, [esp + 0x80]
            //   4533e4               | push                ecx
            //   41c1fc10             | push                0
            //   8d6fff               | dec                 eax

    condition:
        7 of them and filesize < 1581056
}