rule win_alina_pos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.alina_pos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.alina_pos"
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
        $sequence_0 = { 6828010000 8d85d0feffff 6a00 50 e8???????? 83c40c }
            // n = 6, score = 2400
            //   6828010000           | push                0x128
            //   8d85d0feffff         | lea                 eax, dword ptr [ebp - 0x130]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_1 = { e9???????? a1???????? 83e0f7 a3???????? c3 }
            // n = 5, score = 2200
            //   e9????????           |                     
            //   a1????????           |                     
            //   83e0f7               | and                 eax, 0xfffffff7
            //   a3????????           |                     
            //   c3                   | ret                 

        $sequence_2 = { 2bd0 83faff 7306 8bf2 85f6 }
            // n = 5, score = 2000
            //   2bd0                 | sub                 edx, eax
            //   83faff               | cmp                 edx, -1
            //   7306                 | jae                 8
            //   8bf2                 | mov                 esi, edx
            //   85f6                 | test                esi, esi

        $sequence_3 = { 8bd7 2bce 2bc8 51 03fe }
            // n = 5, score = 2000
            //   8bd7                 | mov                 edx, edi
            //   2bce                 | sub                 ecx, esi
            //   2bc8                 | sub                 ecx, eax
            //   51                   | push                ecx
            //   03fe                 | add                 edi, esi

        $sequence_4 = { 03f8 03d0 57 52 e8???????? }
            // n = 5, score = 2000
            //   03f8                 | add                 edi, eax
            //   03d0                 | add                 edx, eax
            //   57                   | push                edi
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_5 = { 3bc1 7763 83ceff 3bc8 }
            // n = 4, score = 2000
            //   3bc1                 | cmp                 eax, ecx
            //   7763                 | ja                  0x65
            //   83ceff               | or                  esi, 0xffffffff
            //   3bc8                 | cmp                 ecx, eax

        $sequence_6 = { 53 ff15???????? 85c0 75cd 56 }
            // n = 5, score = 2000
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   75cd                 | jne                 0xffffffcf
            //   56                   | push                esi

        $sequence_7 = { 39410c 7305 8b4908 eb04 8bd1 8b09 }
            // n = 6, score = 2000
            //   39410c               | cmp                 dword ptr [ecx + 0xc], eax
            //   7305                 | jae                 7
            //   8b4908               | mov                 ecx, dword ptr [ecx + 8]
            //   eb04                 | jmp                 6
            //   8bd1                 | mov                 edx, ecx
            //   8b09                 | mov                 ecx, dword ptr [ecx]

        $sequence_8 = { 51 03fe 03f8 03d0 }
            // n = 4, score = 2000
            //   51                   | push                ecx
            //   03fe                 | add                 edi, esi
            //   03f8                 | add                 edi, eax
            //   03d0                 | add                 edx, eax

        $sequence_9 = { 6800000080 50 ff15???????? 85c0 }
            // n = 4, score = 1600
            //   6800000080           | push                0x80000000
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_10 = { 68???????? 6a0a e8???????? 83c418 }
            // n = 4, score = 1600
            //   68????????           |                     
            //   6a0a                 | push                0xa
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18

        $sequence_11 = { 8b45ec 85c0 7464 03f8 }
            // n = 4, score = 1400
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   85c0                 | test                eax, eax
            //   7464                 | je                  0x66
            //   03f8                 | add                 edi, eax

        $sequence_12 = { ff15???????? 50 6a73 68???????? }
            // n = 4, score = 1400
            //   ff15????????         |                     
            //   50                   | push                eax
            //   6a73                 | push                0x73
            //   68????????           |                     

        $sequence_13 = { 85c0 7406 c70000000000 85c9 7406 }
            // n = 5, score = 1400
            //   85c0                 | test                eax, eax
            //   7406                 | je                  8
            //   c70000000000         | mov                 dword ptr [eax], 0
            //   85c9                 | test                ecx, ecx
            //   7406                 | je                  8

        $sequence_14 = { ff15???????? 50 6a70 68???????? }
            // n = 4, score = 1400
            //   ff15????????         |                     
            //   50                   | push                eax
            //   6a70                 | push                0x70
            //   68????????           |                     

        $sequence_15 = { 8bf0 8d45ec 50 6800040000 }
            // n = 4, score = 1400
            //   8bf0                 | mov                 esi, eax
            //   8d45ec               | lea                 eax, dword ptr [ebp - 0x14]
            //   50                   | push                eax
            //   6800040000           | push                0x400

        $sequence_16 = { 6a13 53 c645f000 c745d00a000000 }
            // n = 4, score = 1400
            //   6a13                 | push                0x13
            //   53                   | push                ebx
            //   c645f000             | mov                 byte ptr [ebp - 0x10], 0
            //   c745d00a000000       | mov                 dword ptr [ebp - 0x30], 0xa

        $sequence_17 = { 85c9 7406 c70100000000 6a00 }
            // n = 4, score = 1400
            //   85c9                 | test                ecx, ecx
            //   7406                 | je                  8
            //   c70100000000         | mov                 dword ptr [ecx], 0
            //   6a00                 | push                0

        $sequence_18 = { c70100000000 6a00 6a00 6a00 6a01 }
            // n = 5, score = 1400
            //   c70100000000         | mov                 dword ptr [ecx], 0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a01                 | push                1

        $sequence_19 = { ff15???????? 85c0 0f95c0 eb02 b001 }
            // n = 5, score = 1300
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f95c0               | setne               al
            //   eb02                 | jmp                 4
            //   b001                 | mov                 al, 1

        $sequence_20 = { 64a300000000 6800100000 e8???????? 8b5d08 }
            // n = 4, score = 1200
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   6800100000           | push                0x1000
            //   e8????????           |                     
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]

        $sequence_21 = { ff15???????? 50 6a5f 68???????? }
            // n = 4, score = 1200
            //   ff15????????         |                     
            //   50                   | push                eax
            //   6a5f                 | push                0x5f
            //   68????????           |                     

        $sequence_22 = { 6810270000 ff15???????? 6a00 6a0f }
            // n = 4, score = 1200
            //   6810270000           | push                0x2710
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6a0f                 | push                0xf

        $sequence_23 = { 8935???????? 68???????? 6a01 ff15???????? }
            // n = 4, score = 1000
            //   8935????????         |                     
            //   68????????           |                     
            //   6a01                 | push                1
            //   ff15????????         |                     

        $sequence_24 = { 8d4720 50 ff15???????? 8b4718 }
            // n = 4, score = 1000
            //   8d4720               | lea                 eax, dword ptr [edi + 0x20]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b4718               | mov                 eax, dword ptr [edi + 0x18]

        $sequence_25 = { 83c418 e8???????? 8b3d???????? 8bf0 }
            // n = 4, score = 1000
            //   83c418               | add                 esp, 0x18
            //   e8????????           |                     
            //   8b3d????????         |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_26 = { 6800000080 6a00 6a00 68???????? 68???????? }
            // n = 5, score = 1000
            //   6800000080           | push                0x80000000
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   68????????           |                     
            //   68????????           |                     

        $sequence_27 = { 85f6 743e 83feff 7439 }
            // n = 4, score = 800
            //   85f6                 | test                esi, esi
            //   743e                 | je                  0x40
            //   83feff               | cmp                 esi, -1
            //   7439                 | je                  0x3b

        $sequence_28 = { 83feff 7439 6828010000 8d85d0feffff }
            // n = 4, score = 800
            //   83feff               | cmp                 esi, -1
            //   7439                 | je                  0x3b
            //   6828010000           | push                0x128
            //   8d85d0feffff         | lea                 eax, dword ptr [ebp - 0x130]

        $sequence_29 = { d1e8 352083b8ed eb02 d1e8 8901 }
            // n = 5, score = 700
            //   d1e8                 | shr                 eax, 1
            //   352083b8ed           | xor                 eax, 0xedb88320
            //   eb02                 | jmp                 4
            //   d1e8                 | shr                 eax, 1
            //   8901                 | mov                 dword ptr [ecx], eax

        $sequence_30 = { e8???????? 50 8d852fffffff 50 8b4df8 }
            // n = 5, score = 600
            //   e8????????           |                     
            //   50                   | lea                 esi, dword ptr [0x15e5a]
            //   8d852fffffff         | lea                 ecx, dword ptr [ebp + 0xc]
            //   50                   | mov                 dword ptr [ebp - 0x13c], eax
            //   8b4df8               | lea                 ecx, dword ptr [ebp - 0xf4]

        $sequence_31 = { e8???????? 89852cfeffff 8b8d2cfeffff 898d28feffff c645fc03 }
            // n = 5, score = 600
            //   e8????????           |                     
            //   89852cfeffff         | mov                 dword ptr [ebp - 0x1d4], eax
            //   8b8d2cfeffff         | mov                 ecx, dword ptr [ebp - 0x1d4]
            //   898d28feffff         | mov                 dword ptr [ebp - 0x1d8], ecx
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3

        $sequence_32 = { 6a00 50 8d4d0c e8???????? 8985c4feffff 8d8d0cffffff 51 }
            // n = 7, score = 600
            //   6a00                 | push                0
            //   50                   | push                eax
            //   8d4d0c               | lea                 ecx, dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   8985c4feffff         | mov                 dword ptr [ebp - 0x13c], eax
            //   8d8d0cffffff         | lea                 ecx, dword ptr [ebp - 0xf4]
            //   51                   | push                ecx

        $sequence_33 = { 83ec0c 8bcc 89a5d8feffff 8b95ccfeffff 52 e8???????? 8985c8feffff }
            // n = 7, score = 600
            //   83ec0c               | sub                 esp, 0xc
            //   8bcc                 | mov                 ecx, esp
            //   89a5d8feffff         | mov                 dword ptr [ebp - 0x128], esp
            //   8b95ccfeffff         | mov                 edx, dword ptr [ebp - 0x134]
            //   52                   | push                edx
            //   e8????????           |                     
            //   8985c8feffff         | mov                 dword ptr [ebp - 0x138], eax

        $sequence_34 = { 894df8 6a00 8b45f8 50 8b4df8 e8???????? 8b4df8 }
            // n = 7, score = 600
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   6a00                 | push                0
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   50                   | push                eax
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   e8????????           |                     
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]

        $sequence_35 = { 8b45e8 8b4ddc 894818 8b450c }
            // n = 4, score = 600
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   8b4ddc               | mov                 ecx, dword ptr [ebp - 0x24]
            //   894818               | mov                 dword ptr [eax + 0x18], ecx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_36 = { e8???????? 83c40c e9???????? 8b4518 3b450c 7753 8b4518 }
            // n = 7, score = 600
            //   e8????????           |                     
            //   83c40c               | pop                 edi
            //   e9????????           |                     
            //   8b4518               | pop                 esi
            //   3b450c               | pop                 ebx
            //   7753                 | add                 esp, 0xc0
            //   8b4518               | mov                 dword ptr [ebp - 0x13c], eax

        $sequence_37 = { 8d4d0c e8???????? 8b45e0 50 8b4dec 51 8b4dec }
            // n = 7, score = 600
            //   8d4d0c               | lea                 ecx, dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   50                   | push                eax
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   51                   | push                ecx
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]

        $sequence_38 = { c1e81f 4403c0 b867666666 41f7e8 c1fa02 }
            // n = 5, score = 100
            //   c1e81f               | dec                 eax
            //   4403c0               | mov                 dword ptr [edx], ecx
            //   b867666666           | dec                 eax
            //   41f7e8               | mov                 dword ptr [edx + 8], ecx
            //   c1fa02               | dec                 eax

        $sequence_39 = { 7529 b988040000 e8???????? 48898424d0000000 488bc8 e8???????? }
            // n = 6, score = 100
            //   7529                 | mov                 dword ptr [ebx], ecx
            //   b988040000           | dec                 eax
            //   e8????????           |                     
            //   48898424d0000000     | lea                 edx, dword ptr [ebx + 8]
            //   488bc8               | xor                 ecx, ecx
            //   e8????????           |                     

        $sequence_40 = { 84c9 752f 488d1dffbc0100 488b0b 4885c9 7410 4883f9ff }
            // n = 7, score = 100
            //   84c9                 | test                cl, cl
            //   752f                 | jne                 0x31
            //   488d1dffbc0100       | dec                 eax
            //   488b0b               | lea                 ebx, dword ptr [0x1bcff]
            //   4885c9               | dec                 eax
            //   7410                 | mov                 ecx, dword ptr [ebx]
            //   4883f9ff             | dec                 eax

        $sequence_41 = { 488945f0 488d1510dd0000 b805000000 894520 894528 488d45e8 }
            // n = 6, score = 100
            //   488945f0             | lea                 ecx, dword ptr [eax + 8]
            //   488d1510dd0000       | jne                 0x2b
            //   b805000000           | mov                 ecx, 0x488
            //   894520               | dec                 eax
            //   894528               | mov                 dword ptr [esp + 0xd0], eax
            //   488d45e8             | dec                 eax

        $sequence_42 = { 48896f10 33d2 48896f18 488bcf e8???????? 48833b10 7318 }
            // n = 7, score = 100
            //   48896f10             | mov                 ecx, eax
            //   33d2                 | shr                 eax, 0x1f
            //   48896f18             | inc                 esp
            //   488bcf               | add                 eax, eax
            //   e8????????           |                     
            //   48833b10             | mov                 eax, 0x66666667
            //   7318                 | inc                 ecx

        $sequence_43 = { 488d0df9790100 48890b 488d5308 33c9 48890a 48894a08 488d4808 }
            // n = 7, score = 100
            //   488d0df9790100       | test                ecx, ecx
            //   48890b               | je                  0x12
            //   488d5308             | dec                 eax
            //   33c9                 | cmp                 ecx, -1
            //   48890a               | dec                 eax
            //   48894a08             | lea                 ecx, dword ptr [0x179f9]
            //   488d4808             | dec                 eax

    condition:
        7 of them and filesize < 2498560
}