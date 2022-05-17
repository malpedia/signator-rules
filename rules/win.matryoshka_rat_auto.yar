rule win_matryoshka_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.matryoshka_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.matryoshka_rat"
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
        $sequence_0 = { b037 c3 b073 c3 }
            // n = 4, score = 400
            //   b037                 | mov                 al, 0x37
            //   c3                   | ret                 
            //   b073                 | mov                 al, 0x73
            //   c3                   | ret                 

        $sequence_1 = { c3 b06f c3 b063 }
            // n = 4, score = 400
            //   c3                   | ret                 
            //   b06f                 | mov                 al, 0x6f
            //   c3                   | ret                 
            //   b063                 | mov                 al, 0x63

        $sequence_2 = { 7407 b902000000 cd29 488d0dc74e0400 }
            // n = 4, score = 200
            //   7407                 | mov                 eax, dword ptr [ebx + 0x20]
            //   b902000000           | je                  9
            //   cd29                 | mov                 eax, 0xa
            //   488d0dc74e0400       | jmp                 0x28

        $sequence_3 = { 8b45f8 8a5430ff 8a0430 8845fe }
            // n = 4, score = 200
            //   8b45f8               | mov                 dword ptr [ebx], esi
            //   8a5430ff             | mov                 dword ptr [edi + 0x34], eax
            //   8a0430               | mov                 edx, ebx
            //   8845fe               | mov                 ecx, edi

        $sequence_4 = { 7407 b80a000000 eb21 48837b2000 }
            // n = 4, score = 200
            //   7407                 | jmp                 0x1e
            //   b80a000000           | dec                 eax
            //   eb21                 | lea                 edx, [0x3ff98]
            //   48837b2000           | je                  9

        $sequence_5 = { 8b45f8 8933 894734 8bd3 8bcf e8???????? 59 }
            // n = 7, score = 200
            //   8b45f8               | inc                 ecx
            //   8933                 | mov                 eax, 1
            //   894734               | dec                 eax
            //   8bd3                 | mov                 ecx, ebp
            //   8bcf                 | je                  9
            //   e8????????           |                     
            //   59                   | mov                 ecx, 2

        $sequence_6 = { 7407 b80d000000 eb16 4c8b0f }
            // n = 4, score = 200
            //   7407                 | dec                 eax
            //   b80d000000           | mov                 ecx, eax
            //   eb16                 | dec                 eax
            //   4c8b0f               | mov                 dword ptr [ebx], eax

        $sequence_7 = { 8b45f8 eb67 019e84af0600 b201 }
            // n = 4, score = 200
            //   8b45f8               | mov                 dword ptr [edi + ebx + 0x6c0], esi
            //   eb67                 | mov                 eax, dword ptr [edi + ebx + 0x6a0]
            //   019e84af0600         | push                dword ptr [ebx + 0x18]
            //   b201                 | mov                 dword ptr [ebp - 0x64], eax

        $sequence_8 = { 7407 b800000800 eb13 488b442460 488b4908 4889442420 e8???????? }
            // n = 7, score = 200
            //   7407                 | je                  9
            //   b800000800           | mov                 eax, 0x80000
            //   eb13                 | jmp                 0x15
            //   488b442460           | dec                 eax
            //   488b4908             | mov                 eax, dword ptr [esp + 0x60]
            //   4889442420           | dec                 eax
            //   e8????????           |                     

        $sequence_9 = { 7407 b800000800 ebec 488b5908 }
            // n = 4, score = 200
            //   7407                 | mov                 ecx, dword ptr [ecx + 8]
            //   b800000800           | dec                 eax
            //   ebec                 | mov                 dword ptr [esp + 0x20], eax
            //   488b5908             | je                  9

        $sequence_10 = { 7407 b80a000000 eb1c 488d1554ff0300 }
            // n = 4, score = 200
            //   7407                 | mov                 ebx, dword ptr [ecx + 8]
            //   b80a000000           | dec                 eax
            //   eb1c                 | mov                 ecx, ebx
            //   488d1554ff0300       | je                  9

        $sequence_11 = { 8b45f8 8d5b04 59 59 }
            // n = 4, score = 200
            //   8b45f8               | mov                 dword ptr [ebp - 0xc], ebx
            //   8d5b04               | mov                 ebx, dword ptr [ebp - 8]
            //   59                   | mov                 eax, dword ptr [ebp - 0x14]
            //   59                   | add                 dword ptr [ebp - 0x18], 4

        $sequence_12 = { 8b45f8 89841fcc060000 89b41fc0060000 8b841fa0060000 }
            // n = 4, score = 200
            //   8b45f8               | je                  9
            //   89841fcc060000       | mov                 ebx, 0xffffff99
            //   89b41fc0060000       | jmp                 0x14
            //   8b841fa0060000       | test                eax, 0xfffffff7

        $sequence_13 = { 8b45f8 8945d4 895df4 8b5df8 }
            // n = 4, score = 200
            //   8b45f8               | int                 0x29
            //   8945d4               | dec                 eax
            //   895df4               | lea                 ecx, [0x44ec7]
            //   8b5df8               | je                  9

    condition:
        7 of them and filesize < 843776
}