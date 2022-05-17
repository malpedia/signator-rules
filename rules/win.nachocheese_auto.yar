rule win_nachocheese_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.nachocheese."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nachocheese"
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
        $sequence_0 = { 8d8424a5110000 6a00 50 c68424ac11000000 }
            // n = 4, score = 300
            //   8d8424a5110000       | lea                 eax, [esp + 0x11a5]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   c68424ac11000000     | mov                 byte ptr [esp + 0x11ac], 0

        $sequence_1 = { fec3 85f6 0f8539ffffff b8???????? 8d5001 8a08 40 }
            // n = 7, score = 300
            //   fec3                 | inc                 bl
            //   85f6                 | test                esi, esi
            //   0f8539ffffff         | jne                 0xffffff3f
            //   b8????????           |                     
            //   8d5001               | lea                 edx, [eax + 1]
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   40                   | inc                 eax

        $sequence_2 = { 8d55f8 52 50 6a02 51 ff15???????? 83f801 }
            // n = 7, score = 300
            //   8d55f8               | lea                 edx, [ebp - 8]
            //   52                   | push                edx
            //   50                   | push                eax
            //   6a02                 | push                2
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   83f801               | cmp                 eax, 1

        $sequence_3 = { 32db 85f6 0f84c7000000 68ff0f0000 }
            // n = 4, score = 300
            //   32db                 | xor                 bl, bl
            //   85f6                 | test                esi, esi
            //   0f84c7000000         | je                  0xcd
            //   68ff0f0000           | push                0xfff

        $sequence_4 = { 7305 83c303 eb1c 81fb00000100 }
            // n = 4, score = 300
            //   7305                 | jae                 7
            //   83c303               | add                 ebx, 3
            //   eb1c                 | jmp                 0x1e
            //   81fb00000100         | cmp                 ebx, 0x10000

        $sequence_5 = { 33c8 894710 8b4708 33c1 }
            // n = 4, score = 300
            //   33c8                 | xor                 ecx, eax
            //   894710               | mov                 dword ptr [edi + 0x10], eax
            //   8b4708               | mov                 eax, dword ptr [edi + 8]
            //   33c1                 | xor                 eax, ecx

        $sequence_6 = { 3d2bc00000 7d1b 3d9c000000 7c07 }
            // n = 4, score = 300
            //   3d2bc00000           | cmp                 eax, 0xc02b
            //   7d1b                 | jge                 0x1d
            //   3d9c000000           | cmp                 eax, 0x9c
            //   7c07                 | jl                  9

        $sequence_7 = { 8d8dfdbfffff 6a00 51 8985f8bfffff c685fcbfffff00 }
            // n = 5, score = 300
            //   8d8dfdbfffff         | lea                 ecx, [ebp - 0x4003]
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   8985f8bfffff         | mov                 dword ptr [ebp - 0x4008], eax
            //   c685fcbfffff00       | mov                 byte ptr [ebp - 0x4004], 0

        $sequence_8 = { 899500ffffff 8985f8feffff a1???????? 898dfcfeffff 8b0d???????? 8d950cffffff 6a00 }
            // n = 7, score = 300
            //   899500ffffff         | mov                 dword ptr [ebp - 0x100], edx
            //   8985f8feffff         | mov                 dword ptr [ebp - 0x108], eax
            //   a1????????           |                     
            //   898dfcfeffff         | mov                 dword ptr [ebp - 0x104], ecx
            //   8b0d????????         |                     
            //   8d950cffffff         | lea                 edx, [ebp - 0xf4]
            //   6a00                 | push                0

        $sequence_9 = { 33c0 c3 05d13fffff 83f801 }
            // n = 4, score = 300
            //   33c0                 | xor                 eax, eax
            //   c3                   | ret                 
            //   05d13fffff           | add                 eax, 0xffff3fd1
            //   83f801               | cmp                 eax, 1

        $sequence_10 = { 2bfa 8d47fd 3901 8901 }
            // n = 4, score = 300
            //   2bfa                 | sub                 edi, edx
            //   8d47fd               | lea                 eax, [edi - 3]
            //   3901                 | cmp                 dword ptr [ecx], eax
            //   8901                 | mov                 dword ptr [ecx], eax

        $sequence_11 = { 3d2cc00000 7f18 3d2bc00000 7d1b }
            // n = 4, score = 300
            //   3d2cc00000           | cmp                 eax, 0xc02c
            //   7f18                 | jg                  0x1a
            //   3d2bc00000           | cmp                 eax, 0xc02b
            //   7d1b                 | jge                 0x1d

        $sequence_12 = { 3d9c000000 7c07 3d9f000000 7e0d }
            // n = 4, score = 300
            //   3d9c000000           | cmp                 eax, 0x9c
            //   7c07                 | jl                  9
            //   3d9f000000           | cmp                 eax, 0x9f
            //   7e0d                 | jle                 0xf

        $sequence_13 = { 51 e8???????? 8bf0 83c420 32db 85f6 }
            // n = 6, score = 300
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c420               | add                 esp, 0x20
            //   32db                 | xor                 bl, bl
            //   85f6                 | test                esi, esi

        $sequence_14 = { 3d9f000000 7e0d 33c0 c3 }
            // n = 4, score = 300
            //   3d9f000000           | cmp                 eax, 0x9f
            //   7e0d                 | jle                 0xf
            //   33c0                 | xor                 eax, eax
            //   c3                   | ret                 

        $sequence_15 = { 8d4df4 51 66c1c008 53 }
            // n = 4, score = 300
            //   8d4df4               | lea                 ecx, [ebp - 0xc]
            //   51                   | push                ecx
            //   66c1c008             | rol                 ax, 8
            //   53                   | push                ebx

    condition:
        7 of them and filesize < 1064960
}