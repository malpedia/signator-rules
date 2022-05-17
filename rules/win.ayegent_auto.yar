rule win_ayegent_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.ayegent."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ayegent"
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
        $sequence_0 = { 56 ffd7 3d08020000 7f44 }
            // n = 4, score = 100
            //   56                   | push                esi
            //   ffd7                 | call                edi
            //   3d08020000           | cmp                 eax, 0x208
            //   7f44                 | jg                  0x46

        $sequence_1 = { 33f6 3bfb 897c241c 0f8cf9000000 56 }
            // n = 5, score = 100
            //   33f6                 | xor                 esi, esi
            //   3bfb                 | cmp                 edi, ebx
            //   897c241c             | mov                 dword ptr [esp + 0x1c], edi
            //   0f8cf9000000         | jl                  0xff
            //   56                   | push                esi

        $sequence_2 = { 6a02 c744241828010000 e8???????? 8bf0 8d442410 }
            // n = 5, score = 100
            //   6a02                 | push                2
            //   c744241828010000     | mov                 dword ptr [esp + 0x18], 0x128
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   8d442410             | lea                 eax, [esp + 0x10]

        $sequence_3 = { aa ff15???????? 8be8 e8???????? }
            // n = 4, score = 100
            //   aa                   | stosb               byte ptr es:[edi], al
            //   ff15????????         |                     
            //   8be8                 | mov                 ebp, eax
            //   e8????????           |                     

        $sequence_4 = { a3???????? ffd6 a3???????? b940000000 33c0 }
            // n = 5, score = 100
            //   a3????????           |                     
            //   ffd6                 | call                esi
            //   a3????????           |                     
            //   b940000000           | mov                 ecx, 0x40
            //   33c0                 | xor                 eax, eax

        $sequence_5 = { 6a00 6a00 ffd7 6aff 50 ffd5 6860ea0000 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ffd7                 | call                edi
            //   6aff                 | push                -1
            //   50                   | push                eax
            //   ffd5                 | call                ebp
            //   6860ea0000           | push                0xea60

        $sequence_6 = { 7e43 e8???????? 8bf8 83c703 ffd5 0fafc7 33d2 }
            // n = 7, score = 100
            //   7e43                 | jle                 0x45
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   83c703               | add                 edi, 3
            //   ffd5                 | call                ebp
            //   0fafc7               | imul                eax, edi
            //   33d2                 | xor                 edx, edx

        $sequence_7 = { 6a04 8d8c2448010000 53 51 ff15???????? }
            // n = 5, score = 100
            //   6a04                 | push                4
            //   8d8c2448010000       | lea                 ecx, [esp + 0x148]
            //   53                   | push                ebx
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_8 = { f3ab 66ab 8b2d???????? 8d942424010000 aa 52 }
            // n = 6, score = 100
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   8b2d????????         |                     
            //   8d942424010000       | lea                 edx, [esp + 0x124]
            //   aa                   | stosb               byte ptr es:[edi], al
            //   52                   | push                edx

        $sequence_9 = { 8b55fc 8a92f8774000 0890619e4000 40 3bc7 }
            // n = 5, score = 100
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8a92f8774000         | mov                 dl, byte ptr [edx + 0x4077f8]
            //   0890619e4000         | or                  byte ptr [eax + 0x409e61], dl
            //   40                   | inc                 eax
            //   3bc7                 | cmp                 eax, edi

    condition:
        7 of them and filesize < 90112
}