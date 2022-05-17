rule win_grillmark_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.grillmark."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.grillmark"
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
        $sequence_0 = { eb63 682c020000 6a40 ff15???????? 8bf8 }
            // n = 5, score = 300
            //   eb63                 | jmp                 0x65
            //   682c020000           | push                0x22c
            //   6a40                 | push                0x40
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax

        $sequence_1 = { e8???????? 83c428 8d85f8fdffff 50 ffd6 8d85f4fcffff }
            // n = 6, score = 300
            //   e8????????           |                     
            //   83c428               | add                 esp, 0x28
            //   8d85f8fdffff         | lea                 eax, [ebp - 0x208]
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   8d85f4fcffff         | lea                 eax, [ebp - 0x30c]

        $sequence_2 = { 5f 7412 83f806 7409 83f809 }
            // n = 5, score = 300
            //   5f                   | pop                 edi
            //   7412                 | je                  0x14
            //   83f806               | cmp                 eax, 6
            //   7409                 | je                  0xb
            //   83f809               | cmp                 eax, 9

        $sequence_3 = { 7444 c745fc08000000 803f00 7426 8345fc04 ff45f8 }
            // n = 6, score = 300
            //   7444                 | je                  0x46
            //   c745fc08000000       | mov                 dword ptr [ebp - 4], 8
            //   803f00               | cmp                 byte ptr [edi], 0
            //   7426                 | je                  0x28
            //   8345fc04             | add                 dword ptr [ebp - 4], 4
            //   ff45f8               | inc                 dword ptr [ebp - 8]

        $sequence_4 = { 7432 57 897508 e8???????? 89049e 59 43 }
            // n = 7, score = 300
            //   7432                 | je                  0x34
            //   57                   | push                edi
            //   897508               | mov                 dword ptr [ebp + 8], esi
            //   e8????????           |                     
            //   89049e               | mov                 dword ptr [esi + ebx*4], eax
            //   59                   | pop                 ecx
            //   43                   | inc                 ebx

        $sequence_5 = { f3ab 66ab aa 6a44 8d45ac }
            // n = 5, score = 300
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al
            //   6a44                 | push                0x44
            //   8d45ac               | lea                 eax, [ebp - 0x54]

        $sequence_6 = { 83c40c 47 43 43 83ff10 7ce4 8bc6 }
            // n = 7, score = 300
            //   83c40c               | add                 esp, 0xc
            //   47                   | inc                 edi
            //   43                   | inc                 ebx
            //   43                   | inc                 ebx
            //   83ff10               | cmp                 edi, 0x10
            //   7ce4                 | jl                  0xffffffe6
            //   8bc6                 | mov                 eax, esi

        $sequence_7 = { 83c420 e9???????? 68???????? ff37 e8???????? 59 85c0 }
            // n = 7, score = 300
            //   83c420               | add                 esp, 0x20
            //   e9????????           |                     
            //   68????????           |                     
            //   ff37                 | push                dword ptr [edi]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax

        $sequence_8 = { 83f801 7505 bb???????? 83f802 7559 85f6 7507 }
            // n = 7, score = 300
            //   83f801               | cmp                 eax, 1
            //   7505                 | jne                 7
            //   bb????????           |                     
            //   83f802               | cmp                 eax, 2
            //   7559                 | jne                 0x5b
            //   85f6                 | test                esi, esi
            //   7507                 | jne                 9

        $sequence_9 = { 85c0 7421 eb9e 8d85ecfeffff 50 8d85bcfdffff }
            // n = 6, score = 300
            //   85c0                 | test                eax, eax
            //   7421                 | je                  0x23
            //   eb9e                 | jmp                 0xffffffa0
            //   8d85ecfeffff         | lea                 eax, [ebp - 0x114]
            //   50                   | push                eax
            //   8d85bcfdffff         | lea                 eax, [ebp - 0x244]

    condition:
        7 of them and filesize < 212992
}