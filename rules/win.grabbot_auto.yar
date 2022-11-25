rule win_grabbot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.grabbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.grabbot"
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
        $sequence_0 = { 83ec70 53 56 c745d04c64724c }
            // n = 4, score = 3600
            //   83ec70               | mov                 word ptr [ebp - 0x180], bx
            //   53                   | mov                 word ptr [ebp - 0x82], bx
            //   56                   | pop                 ebx
            //   c745d04c64724c       | mov                 word ptr [ebp - 0x58], bx

        $sequence_1 = { 8d0477 75e1 8b45fc 81f15e7bec03 81f949b1c76d }
            // n = 5, score = 3600
            //   8d0477               | push                0x65
            //   75e1                 | mov                 word ptr [esp + 0xe], cx
            //   8b45fc               | pop                 ecx
            //   81f15e7bec03         | push                0x67
            //   81f949b1c76d         | mov                 word ptr [esp + 0x10], cx

        $sequence_2 = { 6a01 6a00 ffd0 5b 83c304 ebe9 }
            // n = 6, score = 3600
            //   6a01                 | dec                 eax
            //   6a00                 | mov                 edx, dword ptr [esp + 0x78]
            //   ffd0                 | dec                 eax
            //   5b                   | mov                 eax, dword ptr [ecx]
            //   83c304               | call                dword ptr [eax + 0x30]
            //   ebe9                 | dec                 eax

        $sequence_3 = { 7523 8b8c18a0000000 85c9 0f8489000000 837c187405 0f867e000000 8bbc18a4000000 }
            // n = 7, score = 3600
            //   7523                 | jne                 0x134c
            //   8b8c18a0000000       | dec                 eax
            //   85c9                 | lea                 ecx, [esp + 0xd8]
            //   0f8489000000         | dec                 eax
            //   837c187405           | mov                 ebx, eax
            //   0f867e000000         | dec                 eax
            //   8bbc18a4000000       | mov                 ecx, edi

        $sequence_4 = { 8b4d0c 8b10 51 8b4d08 2bfe 51 }
            // n = 6, score = 3600
            //   8b4d0c               | push                0x65
            //   8b10                 | pop                 ebx
            //   51                   | mov                 word ptr [ebp - 0x22], ax
            //   8b4d08               | push                0x72
            //   2bfe                 | mov                 eax, ebx
            //   51                   | pop                 eax

        $sequence_5 = { d1ea 7303 3355fc e2f7 }
            // n = 4, score = 3600
            //   d1ea                 | test                eax, eax
            //   7303                 | mov                 dword ptr [ebp - 8], ebx
            //   3355fc               | mov                 dword ptr [ebp - 0x1c], ebx
            //   e2f7                 | mov                 dword ptr [ebp - 0xc], ebx

        $sequence_6 = { 8b8c18b0000000 85c9 7460 83bc188400000005 7656 8bbc18b4000000 }
            // n = 6, score = 3600
            //   8b8c18b0000000       | pop                 ecx
            //   85c9                 | test                ebx, ebx
            //   7460                 | je                  0x1fab
            //   83bc188400000005     | and                 dword ptr [ebp - 4], 0
            //   7656                 | push                0
            //   8bbc18b4000000       | lea                 eax, [ebp - 4]

        $sequence_7 = { 682f6f0610 e8???????? 50 e8???????? ff7514 ff7510 ff750c }
            // n = 7, score = 3600
            //   682f6f0610           | inc                 ebp
            //   e8????????           |                     
            //   50                   | xor                 eax, eax
            //   e8????????           |                     
            //   ff7514               | xor                 ecx, ecx
            //   ff7510               | inc                 ecx
            //   ff750c               | lea                 edx, [ecx + 0x1a]

        $sequence_8 = { 668945de 6a00 8d45dc 50 52 ff55f4 85c0 }
            // n = 7, score = 3600
            //   668945de             | pop                 esi
            //   6a00                 | mov                 ecx, dword ptr [ebp - 4]
            //   8d45dc               | push                ecx
            //   50                   | inc                 edi
            //   52                   | cmp                 edi, dword ptr [ebp - 0xc]
            //   ff55f4               | jae                 0x1bd3
            //   85c0                 | mov                 eax, dword ptr [ebp - 0x10]

        $sequence_9 = { 03ca 3bc1 773f 81ec80000000 8bdc }
            // n = 5, score = 3600
            //   03ca                 | push                0xfde9
            //   3bc1                 | lea                 eax, [ebx + 0x20]
            //   773f                 | push                eax
            //   81ec80000000         | lea                 eax, [ebp - 8]
            //   8bdc                 | push                eax

    condition:
        7 of them and filesize < 1335296
}