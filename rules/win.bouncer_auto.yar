rule win_bouncer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.bouncer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bouncer"
        malpedia_rule_date = "20211007"
        malpedia_hash = "e5b790e0f888f252d49063a1251ca60ec2832535"
        malpedia_version = "20211008"
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
        $sequence_0 = { c785fcfeffff01000000 7703 8b7d10 8d85fcfeffff 50 56 }
            // n = 6, score = 100
            //   c785fcfeffff01000000     | mov    dword ptr [ebp - 0x104], 1
            //   7703                 | ja                  5
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]
            //   8d85fcfeffff         | lea                 eax, dword ptr [ebp - 0x104]
            //   50                   | push                eax
            //   56                   | push                esi

        $sequence_1 = { 50 e8???????? 59 40 50 8d45a0 50 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   40                   | inc                 eax
            //   50                   | push                eax
            //   8d45a0               | lea                 eax, dword ptr [ebp - 0x60]
            //   50                   | push                eax

        $sequence_2 = { e8???????? 8d7e1c 57 ff15???????? 59 3bc3 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8d7e1c               | lea                 edi, dword ptr [esi + 0x1c]
            //   57                   | push                edi
            //   ff15????????         |                     
            //   59                   | pop                 ecx
            //   3bc3                 | cmp                 eax, ebx

        $sequence_3 = { ff15???????? 83c440 e9???????? 8d45dc c645dc16 50 895df0 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   83c440               | add                 esp, 0x40
            //   e9????????           |                     
            //   8d45dc               | lea                 eax, dword ptr [ebp - 0x24]
            //   c645dc16             | mov                 byte ptr [ebp - 0x24], 0x16
            //   50                   | push                eax
            //   895df0               | mov                 dword ptr [ebp - 0x10], ebx

        $sequence_4 = { ff15???????? 8d85a4f6ffff 50 8d85a4f8ffff 68???????? }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   8d85a4f6ffff         | lea                 eax, dword ptr [ebp - 0x95c]
            //   50                   | push                eax
            //   8d85a4f8ffff         | lea                 eax, dword ptr [ebp - 0x75c]
            //   68????????           |                     

        $sequence_5 = { 8d45dc ff7508 50 8d85a064ffff 50 e8???????? }
            // n = 6, score = 100
            //   8d45dc               | lea                 eax, dword ptr [ebp - 0x24]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   50                   | push                eax
            //   8d85a064ffff         | lea                 eax, dword ptr [ebp - 0x9b60]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_6 = { 7e33 8d85f4feffff 50 56 e8???????? 85c0 7422 }
            // n = 7, score = 100
            //   7e33                 | jle                 0x35
            //   8d85f4feffff         | lea                 eax, dword ptr [ebp - 0x10c]
            //   50                   | push                eax
            //   56                   | push                esi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7422                 | je                  0x24

        $sequence_7 = { e8???????? 83c43c 3bc3 0f841e060000 0f8c18060000 3b45f8 0f85ea0a0000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c43c               | add                 esp, 0x3c
            //   3bc3                 | cmp                 eax, ebx
            //   0f841e060000         | je                  0x624
            //   0f8c18060000         | jl                  0x61e
            //   3b45f8               | cmp                 eax, dword ptr [ebp - 8]
            //   0f85ea0a0000         | jne                 0xaf0

        $sequence_8 = { a1???????? ff5024 b804030980 ebe0 }
            // n = 4, score = 100
            //   a1????????           |                     
            //   ff5024               | call                dword ptr [eax + 0x24]
            //   b804030980           | mov                 eax, 0x80090304
            //   ebe0                 | jmp                 0xffffffe2

        $sequence_9 = { 6a03 68c8000000 ff75f8 e8???????? 8d45fc 50 ff75f8 }
            // n = 7, score = 100
            //   6a03                 | push                3
            //   68c8000000           | push                0xc8
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   e8????????           |                     
            //   8d45fc               | lea                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax
            //   ff75f8               | push                dword ptr [ebp - 8]

    condition:
        7 of them and filesize < 335872
}