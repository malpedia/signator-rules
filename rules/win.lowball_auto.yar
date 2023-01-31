rule win_lowball_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.lowball."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lowball"
        malpedia_rule_date = "20230124"
        malpedia_hash = "2ee0eebba83dce3d019a90519f2f972c0fcf9686"
        malpedia_version = "20230125"
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
        $sequence_0 = { 8bcb 4f c1e902 f3a5 8bcb 8d84243c090000 83e103 }
            // n = 7, score = 100
            //   8bcb                 | mov                 ecx, ebx
            //   4f                   | dec                 edi
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bcb                 | mov                 ecx, ebx
            //   8d84243c090000       | lea                 eax, [esp + 0x93c]
            //   83e103               | and                 ecx, 3

        $sequence_1 = { 8b1d???????? 83c410 85c0 752d 68b80b0000 }
            // n = 5, score = 100
            //   8b1d????????         |                     
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax
            //   752d                 | jne                 0x2f
            //   68b80b0000           | push                0xbb8

        $sequence_2 = { 51 68???????? aa ff15???????? 83c9ff bf???????? }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   68????????           |                     
            //   aa                   | stosb               byte ptr es:[edi], al
            //   ff15????????         |                     
            //   83c9ff               | or                  ecx, 0xffffffff
            //   bf????????           |                     

        $sequence_3 = { 2bf9 68???????? 8bd9 8bf7 83c9ff }
            // n = 5, score = 100
            //   2bf9                 | sub                 edi, ecx
            //   68????????           |                     
            //   8bd9                 | mov                 ebx, ecx
            //   8bf7                 | mov                 esi, edi
            //   83c9ff               | or                  ecx, 0xffffffff

        $sequence_4 = { 8d542418 f3ab 8d4c2414 c744240800000000 66ab 51 }
            // n = 6, score = 100
            //   8d542418             | lea                 edx, [esp + 0x18]
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8d4c2414             | lea                 ecx, [esp + 0x14]
            //   c744240800000000     | mov                 dword ptr [esp + 8], 0
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   51                   | push                ecx

        $sequence_5 = { ff15???????? 6a00 89442418 ff15???????? 50 ff15???????? }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   89442418             | mov                 dword ptr [esp + 0x18], eax
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_6 = { ff15???????? 57 ff15???????? 57 89442444 e8???????? }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   57                   | push                edi
            //   ff15????????         |                     
            //   57                   | push                edi
            //   89442444             | mov                 dword ptr [esp + 0x44], eax
            //   e8????????           |                     

        $sequence_7 = { 49 6a00 6a00 51 }
            // n = 4, score = 100
            //   49                   | dec                 ecx
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   51                   | push                ecx

        $sequence_8 = { f3a5 8bcb 8d942424020000 83e103 }
            // n = 4, score = 100
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bcb                 | mov                 ecx, ebx
            //   8d942424020000       | lea                 edx, [esp + 0x224]
            //   83e103               | and                 ecx, 3

        $sequence_9 = { ffd6 83c40c 85c0 0f848a000000 6a09 8d8c2428020000 68???????? }
            // n = 7, score = 100
            //   ffd6                 | call                esi
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   0f848a000000         | je                  0x90
            //   6a09                 | push                9
            //   8d8c2428020000       | lea                 ecx, [esp + 0x228]
            //   68????????           |                     

    condition:
        7 of them and filesize < 40960
}