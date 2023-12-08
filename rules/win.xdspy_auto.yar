rule win_xdspy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.xdspy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xdspy"
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
        $sequence_0 = { 8d45ec 50 ff35???????? e8???????? 83f8ff }
            // n = 5, score = 200
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   50                   | push                eax
            //   ff35????????         |                     
            //   e8????????           |                     
            //   83f8ff               | cmp                 eax, -1

        $sequence_1 = { ffb56cd8ffff 8d8570d8ffff 6800040000 6a01 50 e8???????? }
            // n = 6, score = 200
            //   ffb56cd8ffff         | push                dword ptr [ebp - 0x2794]
            //   8d8570d8ffff         | lea                 eax, [ebp - 0x2790]
            //   6800040000           | push                0x400
            //   6a01                 | push                1
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_2 = { 8b36 8bce c1f905 8b0c8d804e4100 }
            // n = 4, score = 200
            //   8b36                 | mov                 esi, dword ptr [esi]
            //   8bce                 | mov                 ecx, esi
            //   c1f905               | sar                 ecx, 5
            //   8b0c8d804e4100       | mov                 ecx, dword ptr [ecx*4 + 0x414e80]

        $sequence_3 = { ff7580 8b3d???????? ffd7 8d4580 50 68???????? 56 }
            // n = 7, score = 200
            //   ff7580               | push                dword ptr [ebp - 0x80]
            //   8b3d????????         |                     
            //   ffd7                 | call                edi
            //   8d4580               | lea                 eax, [ebp - 0x80]
            //   50                   | push                eax
            //   68????????           |                     
            //   56                   | push                esi

        $sequence_4 = { 8d45e0 50 57 8d85e02a0000 50 ff75dc ffd3 }
            // n = 7, score = 200
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   50                   | push                eax
            //   57                   | push                edi
            //   8d85e02a0000         | lea                 eax, [ebp + 0x2ae0]
            //   50                   | push                eax
            //   ff75dc               | push                dword ptr [ebp - 0x24]
            //   ffd3                 | call                ebx

        $sequence_5 = { 83c414 83c8ff e9???????? 8bc6 c1f805 57 8d3c85804e4100 }
            // n = 7, score = 200
            //   83c414               | add                 esp, 0x14
            //   83c8ff               | or                  eax, 0xffffffff
            //   e9????????           |                     
            //   8bc6                 | mov                 eax, esi
            //   c1f805               | sar                 eax, 5
            //   57                   | push                edi
            //   8d3c85804e4100       | lea                 edi, [eax*4 + 0x414e80]

        $sequence_6 = { 8b4de0 8d0c8d804e4100 8901 8305????????20 }
            // n = 4, score = 200
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   8d0c8d804e4100       | lea                 ecx, [ecx*4 + 0x414e80]
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8305????????20       |                     

        $sequence_7 = { 8d8510ecffff 57 50 e8???????? ffb56cd8ffff }
            // n = 5, score = 200
            //   8d8510ecffff         | lea                 eax, [ebp - 0x13f0]
            //   57                   | push                edi
            //   50                   | push                eax
            //   e8????????           |                     
            //   ffb56cd8ffff         | push                dword ptr [ebp - 0x2794]

        $sequence_8 = { 0f1f4000 660f1f840000000000 420fb68431309b1700 88840db0080000 488d4901 }
            // n = 5, score = 100
            //   0f1f4000             | jne                 0xfffffff7
            //   660f1f840000000000     | dec    eax
            //   420fb68431309b1700     | lea    ecx, [ebp + 0x8b0]
            //   88840db0080000       | dec                 eax
            //   488d4901             | lea                 edx, [0x171263]

        $sequence_9 = { 488b15???????? 488d8da0080000 ffd0 660f6f0d???????? 488d3550331700 }
            // n = 5, score = 100
            //   488b15????????       |                     
            //   488d8da0080000       | dec                 eax
            //   ffd0                 | lea                 eax, [eax + 1]
            //   660f6f0d????????     |                     
            //   488d3550331700       | cmp                 byte ptr [eax], 0

        $sequence_10 = { c705????????67736666 c705????????6e747764 c705????????73752f65 66c705????????6d6d 488d1563121700 }
            // n = 5, score = 100
            //   c705????????67736666     |     
            //   c705????????6e747764     |     
            //   c705????????73752f65     |     
            //   66c705????????6d6d     |     
            //   488d1563121700       | cmp                 byte ptr [eax], 0

        $sequence_11 = { 488d4901 84c0 75e8 80bd400c000000 488d85400c0000 7413 }
            // n = 6, score = 100
            //   488d4901             | dec                 eax
            //   84c0                 | lea                 ecx, [ecx + 1]
            //   75e8                 | test                al, al
            //   80bd400c000000       | jne                 0xffffffea
            //   488d85400c0000       | cmp                 byte ptr [ebp + 0xc40], 0
            //   7413                 | dec                 eax

        $sequence_12 = { 4883f860 7ccf 488d15f85c1700 488d0d41e60100 4c8d0552e60100 }
            // n = 5, score = 100
            //   4883f860             | jne                 5
            //   7ccf                 | dec                 eax
            //   488d15f85c1700       | lea                 ecx, [ebp + 0x16f0]
            //   488d0d41e60100       | cmp                 ecx, -1
            //   4c8d0552e60100       | je                  0x19f

        $sequence_13 = { fe08 488d4001 803800 75f5 488d8db0080000 ff15???????? }
            // n = 6, score = 100
            //   fe08                 | lea                 eax, [ebp + 0xc40]
            //   488d4001             | je                  0x15
            //   803800               | dec                 byte ptr [eax]
            //   75f5                 | dec                 eax
            //   488d8db0080000       | lea                 eax, [eax + 1]
            //   ff15????????         |                     

        $sequence_14 = { 83f9ff 0f8496010000 ba01000000 448d420f }
            // n = 4, score = 100
            //   83f9ff               | dec                 eax
            //   0f8496010000         | mov                 dword ptr [esp + 0xa8], eax
            //   ba01000000           | nop                 dword ptr [eax + eax]
            //   448d420f             | dec                 byte ptr [eax]

        $sequence_15 = { 33c9 ff15???????? 48898424a8000000 660f6f05???????? }
            // n = 4, score = 100
            //   33c9                 | nop                 dword ptr [eax]
            //   ff15????????         |                     
            //   48898424a8000000     | nop                 word ptr [eax + eax]
            //   660f6f05????????     |                     

    condition:
        7 of them and filesize < 3244032
}