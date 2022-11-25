rule win_troldesh_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.troldesh."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.troldesh"
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
        $sequence_0 = { ebe3 55 8bec b8c8000000 e8???????? 53 56 }
            // n = 7, score = 600
            //   ebe3                 | jmp                 0xffffffe5
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   b8c8000000           | mov                 eax, 0xc8
            //   e8????????           |                     
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_1 = { ff7608 57 e8???????? 8b5d08 83c40c 6a00 81c76c870000 }
            // n = 7, score = 600
            //   ff7608               | push                dword ptr [esi + 8]
            //   57                   | push                edi
            //   e8????????           |                     
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   83c40c               | add                 esp, 0xc
            //   6a00                 | push                0
            //   81c76c870000         | add                 edi, 0x876c

        $sequence_2 = { e9???????? 56 ba???????? 33ff e8???????? 83c404 85c0 }
            // n = 7, score = 600
            //   e9????????           |                     
            //   56                   | push                esi
            //   ba????????           |                     
            //   33ff                 | xor                 edi, edi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax

        $sequence_3 = { e8???????? 8bd8 eb5d 8b4608 8bd0 c1ea02 23d1 }
            // n = 7, score = 600
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   eb5d                 | jmp                 0x5f
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   8bd0                 | mov                 edx, eax
            //   c1ea02               | shr                 edx, 2
            //   23d1                 | and                 edx, ecx

        $sequence_4 = { e8???????? 8906 8b45fc 59 8b480c 56 e8???????? }
            // n = 7, score = 600
            //   e8????????           |                     
            //   8906                 | mov                 dword ptr [esi], eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   59                   | pop                 ecx
            //   8b480c               | mov                 ecx, dword ptr [eax + 0xc]
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_5 = { eb02 ddd8 8b75f8 e8???????? 8b75f4 e8???????? 8b75e0 }
            // n = 7, score = 600
            //   eb02                 | jmp                 4
            //   ddd8                 | fstp                st(0)
            //   8b75f8               | mov                 esi, dword ptr [ebp - 8]
            //   e8????????           |                     
            //   8b75f4               | mov                 esi, dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   8b75e0               | mov                 esi, dword ptr [ebp - 0x20]

        $sequence_6 = { f72e 03c8 13ea 53 6a02 55 51 }
            // n = 7, score = 600
            //   f72e                 | imul                dword ptr [esi]
            //   03c8                 | add                 ecx, eax
            //   13ea                 | adc                 ebp, edx
            //   53                   | push                ebx
            //   6a02                 | push                2
            //   55                   | push                ebp
            //   51                   | push                ecx

        $sequence_7 = { e9???????? 8b4d0c 33c0 3919 0f95c0 89878c040000 e9???????? }
            // n = 7, score = 600
            //   e9????????           |                     
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   33c0                 | xor                 eax, eax
            //   3919                 | cmp                 dword ptr [ecx], ebx
            //   0f95c0               | setne               al
            //   89878c040000         | mov                 dword ptr [edi + 0x48c], eax
            //   e9????????           |                     

        $sequence_8 = { e8???????? e9???????? 215e0c 6a14 897e04 58 8b4df4 }
            // n = 7, score = 600
            //   e8????????           |                     
            //   e9????????           |                     
            //   215e0c               | and                 dword ptr [esi + 0xc], ebx
            //   6a14                 | push                0x14
            //   897e04               | mov                 dword ptr [esi + 4], edi
            //   58                   | pop                 eax
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_9 = { ffb708010000 038ffc000000 51 50 e8???????? 83c40c eb13 }
            // n = 7, score = 600
            //   ffb708010000         | push                dword ptr [edi + 0x108]
            //   038ffc000000         | add                 ecx, dword ptr [edi + 0xfc]
            //   51                   | push                ecx
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   eb13                 | jmp                 0x15

    condition:
        7 of them and filesize < 3915776
}