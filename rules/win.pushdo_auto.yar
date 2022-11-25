rule win_pushdo_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.pushdo."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pushdo"
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
        $sequence_0 = { f7f9 33c9 ba88020000 f7e2 0f90c1 }
            // n = 5, score = 1200
            //   f7f9                 | idiv                ecx
            //   33c9                 | xor                 ecx, ecx
            //   ba88020000           | mov                 edx, 0x288
            //   f7e2                 | mul                 edx
            //   0f90c1               | seto                cl

        $sequence_1 = { 50 ff15???????? 33d2 b9ffff0000 }
            // n = 4, score = 1200
            //   50                   | push                eax
            //   ff15????????         |                     
            //   33d2                 | xor                 edx, edx
            //   b9ffff0000           | mov                 ecx, 0xffff

        $sequence_2 = { 8b45fc b10b d3c0 61 }
            // n = 4, score = 1100
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   b10b                 | mov                 cl, 0xb
            //   d3c0                 | rol                 eax, cl
            //   61                   | popal               

        $sequence_3 = { 8d85f0feffff 2bd0 8b4df8 83c101 894df8 }
            // n = 5, score = 800
            //   8d85f0feffff         | lea                 eax, [ebp - 0x110]
            //   2bd0                 | sub                 edx, eax
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   83c101               | add                 ecx, 1
            //   894df8               | mov                 dword ptr [ebp - 8], ecx

        $sequence_4 = { 8b4df4 0fbe940df0feffff 0395e8feffff 81e2ff000000 8995e8feffff 8b45f4 8a8c05f0feffff }
            // n = 7, score = 800
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   0fbe940df0feffff     | movsx               edx, byte ptr [ebp + ecx - 0x110]
            //   0395e8feffff         | add                 edx, dword ptr [ebp - 0x118]
            //   81e2ff000000         | and                 edx, 0xff
            //   8995e8feffff         | mov                 dword ptr [ebp - 0x118], edx
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8a8c05f0feffff       | mov                 cl, byte ptr [ebp + eax - 0x110]

        $sequence_5 = { 034dfc 0fbe11 8b85e8feffff 0fbe8c05f0feffff 8b45f4 }
            // n = 5, score = 800
            //   034dfc               | add                 ecx, dword ptr [ebp - 4]
            //   0fbe11               | movsx               edx, byte ptr [ecx]
            //   8b85e8feffff         | mov                 eax, dword ptr [ebp - 0x118]
            //   0fbe8c05f0feffff     | movsx               ecx, byte ptr [ebp + eax - 0x110]
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_6 = { 8a8c05f0feffff 888deffeffff 8b95e8feffff 8b45fc 8a8c05f0feffff }
            // n = 5, score = 800
            //   8a8c05f0feffff       | mov                 cl, byte ptr [ebp + eax - 0x110]
            //   888deffeffff         | mov                 byte ptr [ebp - 0x111], cl
            //   8b95e8feffff         | mov                 edx, dword ptr [ebp - 0x118]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8a8c05f0feffff       | mov                 cl, byte ptr [ebp + eax - 0x110]

        $sequence_7 = { 03c8 81e1ff000000 0fbe8c0df0feffff 33d1 8b450c 0345fc 8810 }
            // n = 7, score = 800
            //   03c8                 | add                 ecx, eax
            //   81e1ff000000         | and                 ecx, 0xff
            //   0fbe8c0df0feffff     | movsx               ecx, byte ptr [ebp + ecx - 0x110]
            //   33d1                 | xor                 edx, ecx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   0345fc               | add                 eax, dword ptr [ebp - 4]
            //   8810                 | mov                 byte ptr [eax], dl

        $sequence_8 = { 894df8 81faff000000 7d12 8b55f8 }
            // n = 4, score = 800
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   81faff000000         | cmp                 edx, 0xff
            //   7d12                 | jge                 0x14
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]

        $sequence_9 = { 8d45fc 50 ff75fc 8d85f4f7ffff 50 6a01 }
            // n = 6, score = 500
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   8d85f4f7ffff         | lea                 eax, [ebp - 0x80c]
            //   50                   | push                eax
            //   6a01                 | push                1

        $sequence_10 = { 395d10 0f84cc000000 395810 0f84c3000000 }
            // n = 4, score = 500
            //   395d10               | cmp                 dword ptr [ebp + 0x10], ebx
            //   0f84cc000000         | je                  0xd2
            //   395810               | cmp                 dword ptr [eax + 0x10], ebx
            //   0f84c3000000         | je                  0xc9

        $sequence_11 = { 5f 5e 85c0 7529 8d45e0 50 }
            // n = 6, score = 500
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   85c0                 | test                eax, eax
            //   7529                 | jne                 0x2b
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   50                   | push                eax

        $sequence_12 = { 0f84a3000000 39750c 0f849a000000 397510 0f8491000000 }
            // n = 5, score = 500
            //   0f84a3000000         | je                  0xa9
            //   39750c               | cmp                 dword ptr [ebp + 0xc], esi
            //   0f849a000000         | je                  0xa0
            //   397510               | cmp                 dword ptr [ebp + 0x10], esi
            //   0f8491000000         | je                  0x97

        $sequence_13 = { 52 8d8588fbffff 50 e8???????? }
            // n = 4, score = 500
            //   52                   | push                edx
            //   8d8588fbffff         | lea                 eax, [ebp - 0x478]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_14 = { 0f84a3000000 8b35???????? 8d45f8 50 8d85f4fbffff 50 }
            // n = 6, score = 500
            //   0f84a3000000         | je                  0xa9
            //   8b35????????         |                     
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   8d85f4fbffff         | lea                 eax, [ebp - 0x40c]
            //   50                   | push                eax

        $sequence_15 = { 8bff 55 8bec 8b450c 0fbe08 85c9 }
            // n = 6, score = 200
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   0fbe08               | movsx               ecx, byte ptr [eax]
            //   85c9                 | test                ecx, ecx

        $sequence_16 = { 83c002 3b45f0 7d0c 8b4df8 034df4 }
            // n = 5, score = 200
            //   83c002               | add                 eax, 2
            //   3b45f0               | cmp                 eax, dword ptr [ebp - 0x10]
            //   7d0c                 | jge                 0xe
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   034df4               | add                 ecx, dword ptr [ebp - 0xc]

        $sequence_17 = { 7f09 0fbe4508 83e847 eb2a 0fbe4d08 }
            // n = 5, score = 200
            //   7f09                 | jg                  0xb
            //   0fbe4508             | movsx               eax, byte ptr [ebp + 8]
            //   83e847               | sub                 eax, 0x47
            //   eb2a                 | jmp                 0x2c
            //   0fbe4d08             | movsx               ecx, byte ptr [ebp + 8]

        $sequence_18 = { 8945fc 8b4dfc 8b550c 8a02 8801 8b4dfc 0fbe11 }
            // n = 7, score = 200
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   8a02                 | mov                 al, byte ptr [edx]
            //   8801                 | mov                 byte ptr [ecx], al
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   0fbe11               | movsx               edx, byte ptr [ecx]

        $sequence_19 = { 6a00 8b4d18 51 8b5514 52 8b45ec 50 }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   8b4d18               | mov                 ecx, dword ptr [ebp + 0x18]
            //   51                   | push                ecx
            //   8b5514               | mov                 edx, dword ptr [ebp + 0x14]
            //   52                   | push                edx
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   50                   | push                eax

        $sequence_20 = { eb20 8b5508 83c208 52 8b4508 83c00c }
            // n = 6, score = 200
            //   eb20                 | jmp                 0x22
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   83c208               | add                 edx, 8
            //   52                   | push                edx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83c00c               | add                 eax, 0xc

        $sequence_21 = { 89040a 8b45f4 c1e005 8b4df4 }
            // n = 4, score = 200
            //   89040a               | mov                 dword ptr [edx + ecx], eax
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   c1e005               | shl                 eax, 5
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

    condition:
        7 of them and filesize < 163840
}