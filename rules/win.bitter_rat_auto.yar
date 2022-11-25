rule win_bitter_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.bitter_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bitter_rat"
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
        $sequence_0 = { 56 57 33f6 33ff 897dfc 3b1cfd283a4500 7409 }
            // n = 7, score = 200
            //   56                   | push                esi
            //   57                   | push                edi
            //   33f6                 | xor                 esi, esi
            //   33ff                 | xor                 edi, edi
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   3b1cfd283a4500       | cmp                 ebx, dword ptr [edi*8 + 0x453a28]
            //   7409                 | je                  0xb

        $sequence_1 = { 83c404 89859cfeffff 68???????? 8b859cfeffff 50 e8???????? 83c408 }
            // n = 7, score = 200
            //   83c404               | add                 esp, 4
            //   89859cfeffff         | mov                 dword ptr [ebp - 0x164], eax
            //   68????????           |                     
            //   8b859cfeffff         | mov                 eax, dword ptr [ebp - 0x164]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_2 = { e8???????? 83c40c 5f 5e 5b 81c4fc000000 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   81c4fc000000         | add                 esp, 0xfc

        $sequence_3 = { 8d45e8 50 8b8dbcfbffff 51 8d95e0fbffff }
            // n = 5, score = 200
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   50                   | push                eax
            //   8b8dbcfbffff         | mov                 ecx, dword ptr [ebp - 0x444]
            //   51                   | push                ecx
            //   8d95e0fbffff         | lea                 edx, [ebp - 0x420]

        $sequence_4 = { 743c c605????????01 8b45f8 50 e8???????? 83c404 e8???????? }
            // n = 7, score = 200
            //   743c                 | je                  0x3e
            //   c605????????01       |                     
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   e8????????           |                     

        $sequence_5 = { 8d8dc0feffff 51 e8???????? 83c40c 8d85c0feffff 50 }
            // n = 6, score = 200
            //   8d8dc0feffff         | lea                 ecx, [ebp - 0x140]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d85c0feffff         | lea                 eax, [ebp - 0x140]
            //   50                   | push                eax

        $sequence_6 = { 8945e0 8bf4 6a6b 8b4508 50 ff15???????? 3bf4 }
            // n = 7, score = 200
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   8bf4                 | mov                 esi, esp
            //   6a6b                 | push                0x6b
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   3bf4                 | cmp                 esi, esp

        $sequence_7 = { b97c230000 f7f9 8985e0f8ffff 8b85ecf8ffff 99 }
            // n = 5, score = 200
            //   b97c230000           | mov                 ecx, 0x237c
            //   f7f9                 | idiv                ecx
            //   8985e0f8ffff         | mov                 dword ptr [ebp - 0x720], eax
            //   8b85ecf8ffff         | mov                 eax, dword ptr [ebp - 0x714]
            //   99                   | cdq                 

        $sequence_8 = { f3ab c745f80a000000 6a02 a1???????? 0345f8 50 68???????? }
            // n = 7, score = 200
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   c745f80a000000       | mov                 dword ptr [ebp - 8], 0xa
            //   6a02                 | push                2
            //   a1????????           |                     
            //   0345f8               | add                 eax, dword ptr [ebp - 8]
            //   50                   | push                eax
            //   68????????           |                     

        $sequence_9 = { 50 ff15???????? 3bf4 e8???????? 837de800 742c 8bf4 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   ff15????????         |                     
            //   3bf4                 | cmp                 esi, esp
            //   e8????????           |                     
            //   837de800             | cmp                 dword ptr [ebp - 0x18], 0
            //   742c                 | je                  0x2e
            //   8bf4                 | mov                 esi, esp

    condition:
        7 of them and filesize < 1130496
}