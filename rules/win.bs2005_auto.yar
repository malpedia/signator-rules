rule win_bs2005_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.bs2005."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bs2005"
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
        $sequence_0 = { 85c0 7848 8b45e4 8b08 8d55e8 }
            // n = 5, score = 100
            //   85c0                 | test                eax, eax
            //   7848                 | js                  0x4a
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8d55e8               | lea                 edx, [ebp - 0x18]

        $sequence_1 = { 8b874c060000 8b08 81c154010400 8bc1 8d7001 8d4900 }
            // n = 6, score = 100
            //   8b874c060000         | mov                 eax, dword ptr [edi + 0x64c]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   81c154010400         | add                 ecx, 0x40154
            //   8bc1                 | mov                 eax, ecx
            //   8d7001               | lea                 esi, [eax + 1]
            //   8d4900               | lea                 ecx, [ecx]

        $sequence_2 = { 40 84c9 75f5 6a01 }
            // n = 4, score = 100
            //   40                   | inc                 eax
            //   84c9                 | test                cl, cl
            //   75f5                 | jne                 0xfffffff7
            //   6a01                 | push                1

        $sequence_3 = { 8b5604 57 8b7e08 895dec }
            // n = 4, score = 100
            //   8b5604               | mov                 edx, dword ptr [esi + 4]
            //   57                   | push                edi
            //   8b7e08               | mov                 edi, dword ptr [esi + 8]
            //   895dec               | mov                 dword ptr [ebp - 0x14], ebx

        $sequence_4 = { 8b874c060000 e8???????? 8b874c060000 8b08 83b94400040000 0f8729ffffff 8b9754060000 }
            // n = 7, score = 100
            //   8b874c060000         | mov                 eax, dword ptr [edi + 0x64c]
            //   e8????????           |                     
            //   8b874c060000         | mov                 eax, dword ptr [edi + 0x64c]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   83b94400040000       | cmp                 dword ptr [ecx + 0x40044], 0
            //   0f8729ffffff         | ja                  0xffffff2f
            //   8b9754060000         | mov                 edx, dword ptr [edi + 0x654]

        $sequence_5 = { c60000 40 49 75f9 8b8354060000 }
            // n = 5, score = 100
            //   c60000               | mov                 byte ptr [eax], 0
            //   40                   | inc                 eax
            //   49                   | dec                 ecx
            //   75f9                 | jne                 0xfffffffb
            //   8b8354060000         | mov                 eax, dword ptr [ebx + 0x654]

        $sequence_6 = { 56 81c344050000 53 8d85f0feffff 68???????? 50 }
            // n = 6, score = 100
            //   56                   | push                esi
            //   81c344050000         | add                 ebx, 0x544
            //   53                   | push                ebx
            //   8d85f0feffff         | lea                 eax, [ebp - 0x110]
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_7 = { 75f9 2bc6 40 50 8b874c060000 51 8b08 }
            // n = 7, score = 100
            //   75f9                 | jne                 0xfffffffb
            //   2bc6                 | sub                 eax, esi
            //   40                   | inc                 eax
            //   50                   | push                eax
            //   8b874c060000         | mov                 eax, dword ptr [edi + 0x64c]
            //   51                   | push                ecx
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_8 = { 56 50 8b412c ffd0 56 8b35???????? ffd6 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   50                   | push                eax
            //   8b412c               | mov                 eax, dword ptr [ecx + 0x2c]
            //   ffd0                 | call                eax
            //   56                   | push                esi
            //   8b35????????         |                     
            //   ffd6                 | call                esi

        $sequence_9 = { 8d55e4 52 6a04 6a00 }
            // n = 4, score = 100
            //   8d55e4               | lea                 edx, [ebp - 0x1c]
            //   52                   | push                edx
            //   6a04                 | push                4
            //   6a00                 | push                0

    condition:
        7 of them and filesize < 212992
}