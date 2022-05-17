rule win_xdspy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.xdspy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xdspy"
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
        $sequence_0 = { 7420 2d02010000 ff7514 ff7510 7405 }
            // n = 5, score = 200
            //   7420                 | je                  0x22
            //   2d02010000           | sub                 eax, 0x102
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   7405                 | je                  7

        $sequence_1 = { ff75c8 ffd6 33c0 40 8b8d2c2f0000 5f }
            // n = 6, score = 200
            //   ff75c8               | push                dword ptr [ebp - 0x38]
            //   ffd6                 | call                esi
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax
            //   8b8d2c2f0000         | mov                 ecx, dword ptr [ebp + 0x2f2c]
            //   5f                   | pop                 edi

        $sequence_2 = { a1???????? 33c5 898598550000 8b85a4550000 53 }
            // n = 5, score = 200
            //   a1????????           |                     
            //   33c5                 | xor                 eax, ebp
            //   898598550000         | mov                 dword ptr [ebp + 0x5598], eax
            //   8b85a4550000         | mov                 eax, dword ptr [ebp + 0x55a4]
            //   53                   | push                ebx

        $sequence_3 = { 8b07 8bc8 c1f905 83e01f c1e006 8b0c8d804e4100 8d440104 }
            // n = 7, score = 200
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   8bc8                 | mov                 ecx, eax
            //   c1f905               | sar                 ecx, 5
            //   83e01f               | and                 eax, 0x1f
            //   c1e006               | shl                 eax, 6
            //   8b0c8d804e4100       | mov                 ecx, dword ptr [ecx*4 + 0x414e80]
            //   8d440104             | lea                 eax, [ecx + eax + 4]

        $sequence_4 = { 56 57 8bbda0260000 be???????? 8d4584 56 }
            // n = 6, score = 200
            //   56                   | push                esi
            //   57                   | push                edi
            //   8bbda0260000         | mov                 edi, dword ptr [ebp + 0x26a0]
            //   be????????           |                     
            //   8d4584               | lea                 eax, [ebp - 0x7c]
            //   56                   | push                esi

        $sequence_5 = { 83c414 33c0 eb1a 8bc8 83e01f c1f905 8b0c8d804e4100 }
            // n = 7, score = 200
            //   83c414               | add                 esp, 0x14
            //   33c0                 | xor                 eax, eax
            //   eb1a                 | jmp                 0x1c
            //   8bc8                 | mov                 ecx, eax
            //   83e01f               | and                 eax, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   8b0c8d804e4100       | mov                 ecx, dword ptr [ecx*4 + 0x414e80]

        $sequence_6 = { ff15???????? 5e c9 c3 55 8dac24d0d0ffff b8b02f0000 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   5e                   | pop                 esi
            //   c9                   | leave               
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8dac24d0d0ffff       | lea                 ebp, [esp - 0x2f30]
            //   b8b02f0000           | mov                 eax, 0x2fb0

        $sequence_7 = { 33f6 8d85f8260000 56 50 }
            // n = 4, score = 200
            //   33f6                 | xor                 esi, esi
            //   8d85f8260000         | lea                 eax, [ebp + 0x26f8]
            //   56                   | push                esi
            //   50                   | push                eax

        $sequence_8 = { 420fb7843978250200 6683e832 66890419 4883c102 4883f916 7ce5 }
            // n = 6, score = 100
            //   420fb7843978250200     | dec    eax
            //   6683e832             | inc                 ecx
            //   66890419             | dec                 eax
            //   4883c102             | add                 eax, 2
            //   4883f916             | mov                 edx, 0x72
            //   7ce5                 | mov                 eax, 0x38

        $sequence_9 = { 3bfe 0f8531fdffff e8???????? b801000000 488bbc24804f0000 }
            // n = 5, score = 100
            //   3bfe                 | dec                 eax
            //   0f8531fdffff         | lea                 edx, [ebp + 0x6c0]
            //   e8????????           |                     
            //   b801000000           | dec                 eax
            //   488bbc24804f0000     | mov                 ecx, eax

        $sequence_10 = { 488d95c0060000 488bc8 ff15???????? eb03 488bc3 488d0d78590700 }
            // n = 6, score = 100
            //   488d95c0060000       | sub                 ax, 0x32
            //   488bc8               | mov                 word ptr [ecx + ebx], ax
            //   ff15????????         |                     
            //   eb03                 | dec                 eax
            //   488bc3               | add                 ecx, 2
            //   488d0d78590700       | dec                 eax

        $sequence_11 = { 66443b0402 0f84f4000000 66443b00 0f84ea000000 48ffc1 4883c002 }
            // n = 6, score = 100
            //   66443b0402           | dec                 eax
            //   0f84f4000000         | lea                 edx, [0x8b76]
            //   66443b00             | inc                 sp
            //   0f84ea000000         | cmp                 eax, dword ptr [edx + eax]
            //   48ffc1               | je                  0xfa
            //   4883c002             | inc                 sp

        $sequence_12 = { ffd0 33d2 488d8dc00f0000 41b800020000 }
            // n = 4, score = 100
            //   ffd0                 | cmp                 ecx, 0x16
            //   33d2                 | jl                  0xfffffff3
            //   488d8dc00f0000       | xor                 ecx, ecx
            //   41b800020000         | psubb               xmm0, xmm6

        $sequence_13 = { f20f59ee f20f5ce9 f2410f1004c1 488d15768b0000 }
            // n = 4, score = 100
            //   f20f59ee             | mulsd               xmm5, xmm6
            //   f20f5ce9             | subsd               xmm5, xmm1
            //   f2410f1004c1         | inc                 ecx
            //   488d15768b0000       | movups              xmm0, xmmword ptr [ecx + eax*8]

        $sequence_14 = { e8???????? f30f6f05???????? 33c9 660ff8c6 f30f7f05???????? }
            // n = 5, score = 100
            //   e8????????           |                     
            //   f30f6f05????????     |                     
            //   33c9                 | inc                 edx
            //   660ff8c6             | movzx               eax, word ptr [ecx + edi + 0x22578]
            //   f30f7f05????????     |                     

        $sequence_15 = { 668935???????? 668905???????? ba72000000 b838000000 66893d???????? }
            // n = 5, score = 100
            //   668935????????       |                     
            //   668905????????       |                     
            //   ba72000000           | cmp                 eax, dword ptr [eax]
            //   b838000000           | je                  0xf0
            //   66893d????????       |                     

    condition:
        7 of them and filesize < 3244032
}