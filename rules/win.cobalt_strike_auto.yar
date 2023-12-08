rule win_cobalt_strike_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.cobalt_strike."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"
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
        $sequence_0 = { 3bc7 750d ff15???????? 3d33270000 }
            // n = 4, score = 1900
            //   3bc7                 | cmp                 eax, edi
            //   750d                 | jne                 0xf
            //   ff15????????         |                     
            //   3d33270000           | cmp                 eax, 0x2733

        $sequence_1 = { e9???????? eb0a b801000000 e9???????? }
            // n = 4, score = 1900
            //   e9????????           |                     
            //   eb0a                 | jmp                 0xc
            //   b801000000           | mov                 eax, 1
            //   e9????????           |                     

        $sequence_2 = { eb06 0fb6c0 83e07f 85c0 745a }
            // n = 5, score = 1100
            //   eb06                 | jmp                 8
            //   0fb6c0               | movzx               eax, al
            //   83e07f               | and                 eax, 0x7f
            //   85c0                 | test                eax, eax
            //   745a                 | je                  0x5c

        $sequence_3 = { eb68 8b45d4 8b482c 894de0 8b45e0 }
            // n = 5, score = 1100
            //   eb68                 | jmp                 0x6a
            //   8b45d4               | mov                 eax, dword ptr [ebp - 0x2c]
            //   8b482c               | mov                 ecx, dword ptr [eax + 0x2c]
            //   894de0               | mov                 dword ptr [ebp - 0x20], ecx
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]

        $sequence_4 = { ff35???????? ffd6 5e e9???????? 55 }
            // n = 5, score = 1100
            //   ff35????????         |                     
            //   ffd6                 | call                esi
            //   5e                   | pop                 esi
            //   e9????????           |                     
            //   55                   | push                ebp

        $sequence_5 = { eb4e 83f824 7f09 c745f403000000 }
            // n = 4, score = 1100
            //   eb4e                 | jmp                 0x50
            //   83f824               | cmp                 eax, 0x24
            //   7f09                 | jg                  0xb
            //   c745f403000000       | mov                 dword ptr [ebp - 0xc], 3

        $sequence_6 = { ff761c 83c004 e8???????? 59 59 83f8ff }
            // n = 6, score = 1100
            //   ff761c               | push                dword ptr [esi + 0x1c]
            //   83c004               | add                 eax, 4
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   83f8ff               | cmp                 eax, -1

        $sequence_7 = { f3a6 744c 8bf0 6a03 bf???????? 59 }
            // n = 6, score = 1100
            //   f3a6                 | repe cmpsb          byte ptr [esi], byte ptr es:[edi]
            //   744c                 | je                  0x4e
            //   8bf0                 | mov                 esi, eax
            //   6a03                 | push                3
            //   bf????????           |                     
            //   59                   | pop                 ecx

        $sequence_8 = { 85c0 741d ff15???????? 85c0 7513 }
            // n = 5, score = 1000
            //   85c0                 | test                eax, eax
            //   741d                 | je                  0x1f
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7513                 | jne                 0x15

        $sequence_9 = { e9???????? 833d????????01 7505 e8???????? }
            // n = 4, score = 1000
            //   e9????????           |                     
            //   833d????????01       |                     
            //   7505                 | jne                 7
            //   e8????????           |                     

        $sequence_10 = { 8bd0 e8???????? 85c0 7e0e }
            // n = 4, score = 1000
            //   8bd0                 | mov                 edx, eax
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7e0e                 | jle                 0x10

        $sequence_11 = { 85c0 7405 e8???????? 8b0d???????? 85c9 }
            // n = 5, score = 900
            //   85c0                 | test                eax, eax
            //   7405                 | je                  7
            //   e8????????           |                     
            //   8b0d????????         |                     
            //   85c9                 | test                ecx, ecx

        $sequence_12 = { f3c3 cc 488bc4 48895808 48896810 48897018 }
            // n = 6, score = 800
            //   f3c3                 | ret                 
            //   cc                   | int3                
            //   488bc4               | dec                 eax
            //   48895808             | mov                 eax, esp
            //   48896810             | dec                 eax
            //   48897018             | mov                 dword ptr [eax + 8], ebx

        $sequence_13 = { c1e903 ffc1 03c1 3d80000000 }
            // n = 4, score = 800
            //   c1e903               | dec                 eax
            //   ffc1                 | mov                 dword ptr [eax + 0x10], ebp
            //   03c1                 | dec                 eax
            //   3d80000000           | mov                 dword ptr [eax + 0x18], esi

        $sequence_14 = { 49ffc7 413bcc 72e9 41894d00 }
            // n = 4, score = 800
            //   49ffc7               | test                eax, eax
            //   413bcc               | jne                 0x1b
            //   72e9                 | test                eax, eax
            //   41894d00             | je                  0x21

        $sequence_15 = { 48895c2448 48895c2440 4889442438 498b06 }
            // n = 4, score = 800
            //   48895c2448           | je                  0x21
            //   48895c2440           | test                eax, eax
            //   4889442438           | test                eax, eax
            //   498b06               | je                  0x21

    condition:
        7 of them and filesize < 1015808
}