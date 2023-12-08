rule win_abaddon_pos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.abaddon_pos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.abaddon_pos"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
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
        $sequence_0 = { 7402 eb27 8b8600010000 03860c010000 89867c010000 8b8684010000 }
            // n = 6, score = 100
            //   7402                 | je                  4
            //   eb27                 | jmp                 0x29
            //   8b8600010000         | mov                 eax, dword ptr [esi + 0x100]
            //   03860c010000         | add                 eax, dword ptr [esi + 0x10c]
            //   89867c010000         | mov                 dword ptr [esi + 0x17c], eax
            //   8b8684010000         | mov                 eax, dword ptr [esi + 0x184]

        $sequence_1 = { ba00000000 eb05 ba01000000 0186ac010000 }
            // n = 4, score = 100
            //   ba00000000           | mov                 edx, 0
            //   eb05                 | jmp                 7
            //   ba01000000           | mov                 edx, 1
            //   0186ac010000         | add                 dword ptr [esi + 0x1ac], eax

        $sequence_2 = { 80beb801000001 751b 80fa30 7205 80fa39 7605 80fa20 }
            // n = 7, score = 100
            //   80beb801000001       | cmp                 byte ptr [esi + 0x1b8], 1
            //   751b                 | jne                 0x1d
            //   80fa30               | cmp                 dl, 0x30
            //   7205                 | jb                  7
            //   80fa39               | cmp                 dl, 0x39
            //   7605                 | jbe                 7
            //   80fa20               | cmp                 dl, 0x20

        $sequence_3 = { 41 89c0 49 c7c100000000 ff15???????? 48 83c420 }
            // n = 7, score = 100
            //   41                   | inc                 ecx
            //   89c0                 | mov                 eax, eax
            //   49                   | dec                 ecx
            //   c7c100000000         | mov                 ecx, 0
            //   ff15????????         |                     
            //   48                   | dec                 eax
            //   83c420               | add                 esp, 0x20

        $sequence_4 = { 48 8986d0050000 48 83ec20 48 c7c100000000 }
            // n = 6, score = 100
            //   48                   | dec                 eax
            //   8986d0050000         | mov                 dword ptr [esi + 0x5d0], eax
            //   48                   | dec                 eax
            //   83ec20               | sub                 esp, 0x20
            //   48                   | dec                 eax
            //   c7c100000000         | mov                 ecx, 0

        $sequence_5 = { 89d8 69c080000000 3d002d0000 7602 eb22 }
            // n = 5, score = 100
            //   89d8                 | mov                 eax, ebx
            //   69c080000000         | imul                eax, eax, 0x80
            //   3d002d0000           | cmp                 eax, 0x2d00
            //   7602                 | jbe                 4
            //   eb22                 | jmp                 0x24

        $sequence_6 = { 7318 807c1e2c41 720c 807c1e2c5a }
            // n = 4, score = 100
            //   7318                 | jae                 0x1a
            //   807c1e2c41           | cmp                 byte ptr [esi + ebx + 0x2c], 0x41
            //   720c                 | jb                  0xe
            //   807c1e2c5a           | cmp                 byte ptr [esi + ebx + 0x2c], 0x5a

        $sequence_7 = { 81bea001000000dc0500 740c 81bea001000000d60600 7508 6a05 ff15???????? 8b86a0010000 }
            // n = 7, score = 100
            //   81bea001000000dc0500     | cmp    dword ptr [esi + 0x1a0], 0x5dc00
            //   740c                 | je                  0xe
            //   81bea001000000d60600     | cmp    dword ptr [esi + 0x1a0], 0x6d600
            //   7508                 | jne                 0xa
            //   6a05                 | push                5
            //   ff15????????         |                     
            //   8b86a0010000         | mov                 eax, dword ptr [esi + 0x1a0]

        $sequence_8 = { 31c9 31d2 80beb401000001 7505 }
            // n = 4, score = 100
            //   31c9                 | xor                 ecx, ecx
            //   31d2                 | xor                 edx, edx
            //   80beb401000001       | cmp                 byte ptr [esi + 0x1b4], 1
            //   7505                 | jne                 7

        $sequence_9 = { ffc3 ebd1 48 31db }
            // n = 4, score = 100
            //   ffc3                 | inc                 ebx
            //   ebd1                 | jmp                 0xffffffd3
            //   48                   | dec                 eax
            //   31db                 | xor                 ebx, ebx

        $sequence_10 = { 8986b0050000 48 83ec20 48 8b8eb0050000 48 }
            // n = 6, score = 100
            //   8986b0050000         | mov                 dword ptr [esi + 0x5b0], eax
            //   48                   | dec                 eax
            //   83ec20               | sub                 esp, 0x20
            //   48                   | dec                 eax
            //   8b8eb0050000         | mov                 ecx, dword ptr [esi + 0x5b0]
            //   48                   | dec                 eax

        $sequence_11 = { 0504d00700 48 8986c8050000 48 0504d00700 48 8986d0050000 }
            // n = 7, score = 100
            //   0504d00700           | add                 eax, 0x7d004
            //   48                   | dec                 eax
            //   8986c8050000         | mov                 dword ptr [esi + 0x5c8], eax
            //   48                   | dec                 eax
            //   0504d00700           | add                 eax, 0x7d004
            //   48                   | dec                 eax
            //   8986d0050000         | mov                 dword ptr [esi + 0x5d0], eax

        $sequence_12 = { 83f800 7502 ebe4 50 ff15???????? 6a00 6a00 }
            // n = 7, score = 100
            //   83f800               | cmp                 eax, 0
            //   7502                 | jne                 4
            //   ebe4                 | jmp                 0xffffffe6
            //   50                   | push                eax
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_13 = { 83c000 48 8b9eb8050000 48 8918 48 }
            // n = 6, score = 100
            //   83c000               | add                 eax, 0
            //   48                   | dec                 eax
            //   8b9eb8050000         | mov                 ebx, dword ptr [esi + 0x5b8]
            //   48                   | dec                 eax
            //   8918                 | mov                 dword ptr [eax], ebx
            //   48                   | dec                 eax

        $sequence_14 = { 0500040000 3b19 730f 311418 }
            // n = 4, score = 100
            //   0500040000           | add                 eax, 0x400
            //   3b19                 | cmp                 ebx, dword ptr [ecx]
            //   730f                 | jae                 0x11
            //   311418               | xor                 dword ptr [eax + ebx], edx

        $sequence_15 = { 720b 803939 7706 fe86a8010000 }
            // n = 4, score = 100
            //   720b                 | jb                  0xd
            //   803939               | cmp                 byte ptr [ecx], 0x39
            //   7706                 | ja                  8
            //   fe86a8010000         | inc                 byte ptr [esi + 0x1a8]

    condition:
        7 of them and filesize < 40960
}