rule win_joanap_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.joanap."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.joanap"
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
        $sequence_0 = { 7719 57 6820bf0200 83c604 50 56 53 }
            // n = 7, score = 100
            //   7719                 | ja                  0x1b
            //   57                   | push                edi
            //   6820bf0200           | push                0x2bf20
            //   83c604               | add                 esi, 4
            //   50                   | push                eax
            //   56                   | push                esi
            //   53                   | push                ebx

        $sequence_1 = { ffd7 85c0 a3???????? 7525 8d4c2468 e8???????? 5f }
            // n = 7, score = 100
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax
            //   a3????????           |                     
            //   7525                 | jne                 0x27
            //   8d4c2468             | lea                 ecx, [esp + 0x68]
            //   e8????????           |                     
            //   5f                   | pop                 edi

        $sequence_2 = { 8d8c24c5000000 51 56 ffd7 85c0 a3???????? 7533 }
            // n = 7, score = 100
            //   8d8c24c5000000       | lea                 ecx, [esp + 0xc5]
            //   51                   | push                ecx
            //   56                   | push                esi
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax
            //   a3????????           |                     
            //   7533                 | jne                 0x35

        $sequence_3 = { 8b442430 3be8 8b44242c 7312 }
            // n = 4, score = 100
            //   8b442430             | mov                 eax, dword ptr [esp + 0x30]
            //   3be8                 | cmp                 ebp, eax
            //   8b44242c             | mov                 eax, dword ptr [esp + 0x2c]
            //   7312                 | jae                 0x14

        $sequence_4 = { ff15???????? 85c0 7422 e9???????? 83fbff }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7422                 | je                  0x24
            //   e9????????           |                     
            //   83fbff               | cmp                 ebx, -1

        $sequence_5 = { 8b8c2404070000 64890d00000000 81c410070000 c3 8d54246b 52 56 }
            // n = 7, score = 100
            //   8b8c2404070000       | mov                 ecx, dword ptr [esp + 0x704]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   81c410070000         | add                 esp, 0x710
            //   c3                   | ret                 
            //   8d54246b             | lea                 edx, [esp + 0x6b]
            //   52                   | push                edx
            //   56                   | push                esi

        $sequence_6 = { e8???????? 83c410 83f8ff 0f8482000000 8b442414 33ff 8b542410 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   83f8ff               | cmp                 eax, -1
            //   0f8482000000         | je                  0x88
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   33ff                 | xor                 edi, edi
            //   8b542410             | mov                 edx, dword ptr [esp + 0x10]

        $sequence_7 = { 7521 83fbff 7407 53 ff15???????? 8d442418 50 }
            // n = 7, score = 100
            //   7521                 | jne                 0x23
            //   83fbff               | cmp                 ebx, -1
            //   7407                 | je                  9
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   8d442418             | lea                 eax, [esp + 0x18]
            //   50                   | push                eax

        $sequence_8 = { 64892500000000 81ecd4040000 56 57 8d4c2468 e8???????? a1???????? }
            // n = 7, score = 100
            //   64892500000000       | mov                 dword ptr fs:[0], esp
            //   81ecd4040000         | sub                 esp, 0x4d4
            //   56                   | push                esi
            //   57                   | push                edi
            //   8d4c2468             | lea                 ecx, [esp + 0x68]
            //   e8????????           |                     
            //   a1????????           |                     

        $sequence_9 = { 81c418020000 c3 a1???????? 6a01 68???????? 896820 e8???????? }
            // n = 7, score = 100
            //   81c418020000         | add                 esp, 0x218
            //   c3                   | ret                 
            //   a1????????           |                     
            //   6a01                 | push                1
            //   68????????           |                     
            //   896820               | mov                 dword ptr [eax + 0x20], ebp
            //   e8????????           |                     

    condition:
        7 of them and filesize < 270336
}