rule win_darkme_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.darkme."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkme"
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
        $sequence_0 = { 8d4dc4 ff15???????? 8d8d74ffffff 51 8d5584 52 8d4594 }
            // n = 7, score = 100
            //   8d4dc4               | lea                 ecx, [ebp - 0x3c]
            //   ff15????????         |                     
            //   8d8d74ffffff         | lea                 ecx, [ebp - 0x8c]
            //   51                   | push                ecx
            //   8d5584               | lea                 edx, [ebp - 0x7c]
            //   52                   | push                edx
            //   8d4594               | lea                 eax, [ebp - 0x6c]

        $sequence_1 = { 897db8 ffd6 68???????? e8???????? 8d55b8 8d4dd8 8945c0 }
            // n = 7, score = 100
            //   897db8               | mov                 dword ptr [ebp - 0x48], edi
            //   ffd6                 | call                esi
            //   68????????           |                     
            //   e8????????           |                     
            //   8d55b8               | lea                 edx, [ebp - 0x48]
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   8945c0               | mov                 dword ptr [ebp - 0x40], eax

        $sequence_2 = { 50 8b956cffffff 8d4dd4 ff15???????? 50 ff15???????? 50 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8b956cffffff         | mov                 edx, dword ptr [ebp - 0x94]
            //   8d4dd4               | lea                 ecx, [ebp - 0x2c]
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   50                   | push                eax

        $sequence_3 = { 8945d4 c745cc08000000 8d55cc 52 8b45ac }
            // n = 5, score = 100
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax
            //   c745cc08000000       | mov                 dword ptr [ebp - 0x34], 8
            //   8d55cc               | lea                 edx, [ebp - 0x34]
            //   52                   | push                edx
            //   8b45ac               | mov                 eax, dword ptr [ebp - 0x54]

        $sequence_4 = { 7428 3d11200000 8bd6 8d4db0 0f84f3000000 ff15???????? 50 }
            // n = 7, score = 100
            //   7428                 | je                  0x2a
            //   3d11200000           | cmp                 eax, 0x2011
            //   8bd6                 | mov                 edx, esi
            //   8d4db0               | lea                 ecx, [ebp - 0x50]
            //   0f84f3000000         | je                  0xf9
            //   ff15????????         |                     
            //   50                   | push                eax

        $sequence_5 = { 8d4588 50 6a03 51 ff15???????? 8bd0 8d4dc4 }
            // n = 7, score = 100
            //   8d4588               | lea                 eax, [ebp - 0x78]
            //   50                   | push                eax
            //   6a03                 | push                3
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8bd0                 | mov                 edx, eax
            //   8d4dc4               | lea                 ecx, [ebp - 0x3c]

        $sequence_6 = { 8b02 8b8d88feffff 8b11 8b0a 50 ff9104030000 50 }
            // n = 7, score = 100
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   8b8d88feffff         | mov                 ecx, dword ptr [ebp - 0x178]
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   8b0a                 | mov                 ecx, dword ptr [edx]
            //   50                   | push                eax
            //   ff9104030000         | call                dword ptr [ecx + 0x304]
            //   50                   | push                eax

        $sequence_7 = { 8945c4 837dc400 7d20 6a28 }
            // n = 4, score = 100
            //   8945c4               | mov                 dword ptr [ebp - 0x3c], eax
            //   837dc400             | cmp                 dword ptr [ebp - 0x3c], 0
            //   7d20                 | jge                 0x22
            //   6a28                 | push                0x28

        $sequence_8 = { 8d459c 50 8d8d5cffffff 51 ff15???????? 83c410 50 }
            // n = 7, score = 100
            //   8d459c               | lea                 eax, [ebp - 0x64]
            //   50                   | push                eax
            //   8d8d5cffffff         | lea                 ecx, [ebp - 0xa4]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   83c410               | add                 esp, 0x10
            //   50                   | push                eax

        $sequence_9 = { 897db8 ffd6 68???????? e8???????? 8d55b8 }
            // n = 5, score = 100
            //   897db8               | mov                 dword ptr [ebp - 0x48], edi
            //   ffd6                 | call                esi
            //   68????????           |                     
            //   e8????????           |                     
            //   8d55b8               | lea                 edx, [ebp - 0x48]

    condition:
        7 of them and filesize < 1515520
}