rule win_dnschanger_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.dnschanger."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dnschanger"
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
        $sequence_0 = { 85c0 750c 5f 83c8ff 5e 81c494000000 }
            // n = 6, score = 100
            //   85c0                 | test                eax, eax
            //   750c                 | jne                 0xe
            //   5f                   | pop                 edi
            //   83c8ff               | or                  eax, 0xffffffff
            //   5e                   | pop                 esi
            //   81c494000000         | add                 esp, 0x94

        $sequence_1 = { 8b4c2414 83c404 8d7801 57 55 }
            // n = 5, score = 100
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   83c404               | add                 esp, 4
            //   8d7801               | lea                 edi, [eax + 1]
            //   57                   | push                edi
            //   55                   | push                ebp

        $sequence_2 = { 7502 b301 57 ff15???????? 85f6 }
            // n = 5, score = 100
            //   7502                 | jne                 4
            //   b301                 | mov                 bl, 1
            //   57                   | push                edi
            //   ff15????????         |                     
            //   85f6                 | test                esi, esi

        $sequence_3 = { 57 e8???????? 8b2d???????? 6880020000 }
            // n = 4, score = 100
            //   57                   | push                edi
            //   e8????????           |                     
            //   8b2d????????         |                     
            //   6880020000           | push                0x280

        $sequence_4 = { 52 6a08 ffd5 50 ffd6 8bf8 }
            // n = 6, score = 100
            //   52                   | push                edx
            //   6a08                 | push                8
            //   ffd5                 | call                ebp
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   8bf8                 | mov                 edi, eax

        $sequence_5 = { 8845ff 84c0 5f 7409 }
            // n = 4, score = 100
            //   8845ff               | mov                 byte ptr [ebp - 1], al
            //   84c0                 | test                al, al
            //   5f                   | pop                 edi
            //   7409                 | je                  0xb

        $sequence_6 = { 8b35???????? 68???????? e8???????? 83c404 85c0 7509 }
            // n = 6, score = 100
            //   8b35????????         |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax
            //   7509                 | jne                 0xb

        $sequence_7 = { 5e c3 8b442408 83600800 c7000c000000 897004 b001 }
            // n = 7, score = 100
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   8b442408             | mov                 eax, dword ptr [esp + 8]
            //   83600800             | and                 dword ptr [eax + 8], 0
            //   c7000c000000         | mov                 dword ptr [eax], 0xc
            //   897004               | mov                 dword ptr [eax + 4], esi
            //   b001                 | mov                 al, 1

        $sequence_8 = { 51 e8???????? 83c408 8b36 43 85f6 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b36                 | mov                 esi, dword ptr [esi]
            //   43                   | inc                 ebx
            //   85f6                 | test                esi, esi

        $sequence_9 = { e8???????? 83c408 81c604020000 4b 75e7 8b35???????? ffd6 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   81c604020000         | add                 esi, 0x204
            //   4b                   | dec                 ebx
            //   75e7                 | jne                 0xffffffe9
            //   8b35????????         |                     
            //   ffd6                 | call                esi

    condition:
        7 of them and filesize < 49152
}