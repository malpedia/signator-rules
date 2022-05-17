rule win_sysraw_stealer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.sysraw_stealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sysraw_stealer"
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
        $sequence_0 = { c7406c00000008 c7407000000010 c7407400000020 c7407800000040 8b467c c700982f8a42 c7400491443771 }
            // n = 7, score = 700
            //   c7406c00000008       | mov                 dword ptr [eax + 0x6c], 0x8000000
            //   c7407000000010       | mov                 dword ptr [eax + 0x70], 0x10000000
            //   c7407400000020       | mov                 dword ptr [eax + 0x74], 0x20000000
            //   c7407800000040       | mov                 dword ptr [eax + 0x78], 0x40000000
            //   8b467c               | mov                 eax, dword ptr [esi + 0x7c]
            //   c700982f8a42         | mov                 dword ptr [eax], 0x428a2f98
            //   c7400491443771       | mov                 dword ptr [eax + 4], 0x71374491

        $sequence_1 = { c7410c3af54fa5 8b5590 c742107f520e51 8b4590 c740148c68059b 8b4d90 }
            // n = 6, score = 700
            //   c7410c3af54fa5       | mov                 dword ptr [ecx + 0xc], 0xa54ff53a
            //   8b5590               | mov                 edx, dword ptr [ebp - 0x70]
            //   c742107f520e51       | mov                 dword ptr [edx + 0x10], 0x510e527f
            //   8b4590               | mov                 eax, dword ptr [ebp - 0x70]
            //   c740148c68059b       | mov                 dword ptr [eax + 0x14], 0x9b05688c
            //   8b4d90               | mov                 ecx, dword ptr [ebp - 0x70]

        $sequence_2 = { 8d8de8feffff ffd6 8b4590 8d8d70feffff 83c018 }
            // n = 5, score = 700
            //   8d8de8feffff         | lea                 ecx, [ebp - 0x118]
            //   ffd6                 | call                esi
            //   8b4590               | mov                 eax, dword ptr [ebp - 0x70]
            //   8d8d70feffff         | lea                 ecx, [ebp - 0x190]
            //   83c018               | add                 eax, 0x18

        $sequence_3 = { 56 ff5138 5f 5e }
            // n = 4, score = 700
            //   56                   | push                esi
            //   ff5138               | call                dword ptr [ecx + 0x38]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_4 = { 8b1d???????? 50 51 c745ec02000000 ffd3 85c0 7503 }
            // n = 7, score = 700
            //   8b1d????????         |                     
            //   50                   | push                eax
            //   51                   | push                ecx
            //   c745ec02000000       | mov                 dword ptr [ebp - 0x14], 2
            //   ffd3                 | call                ebx
            //   85c0                 | test                eax, eax
            //   7503                 | jne                 5

        $sequence_5 = { 25ffffff3f 81e1ffffff3f 81e700000040 81e300000040 }
            // n = 4, score = 700
            //   25ffffff3f           | and                 eax, 0x3fffffff
            //   81e1ffffff3f         | and                 ecx, 0x3fffffff
            //   81e700000040         | and                 edi, 0x40000000
            //   81e300000040         | and                 ebx, 0x40000000

        $sequence_6 = { 894de4 ba3f000000 3bca 0f8f0c020000 83f910 7d19 8b45e0 }
            // n = 7, score = 700
            //   894de4               | mov                 dword ptr [ebp - 0x1c], ecx
            //   ba3f000000           | mov                 edx, 0x3f
            //   3bca                 | cmp                 ecx, edx
            //   0f8f0c020000         | jg                  0x212
            //   83f910               | cmp                 ecx, 0x10
            //   7d19                 | jge                 0x1b
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]

        $sequence_7 = { 8b548ac0 8b8d50feffff 52 51 }
            // n = 4, score = 700
            //   8b548ac0             | mov                 edx, dword ptr [edx + ecx*4 - 0x40]
            //   8b8d50feffff         | mov                 ecx, dword ptr [ebp - 0x1b0]
            //   52                   | push                edx
            //   51                   | push                ecx

        $sequence_8 = { 8b3d???????? 33c0 56 8945e4 8945d4 8945d0 8945bc }
            // n = 7, score = 700
            //   8b3d????????         |                     
            //   33c0                 | xor                 eax, eax
            //   56                   | push                esi
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax
            //   8945bc               | mov                 dword ptr [ebp - 0x44], eax

        $sequence_9 = { ffd6 50 ffd7 8bd0 8d8d58ffffff ffd6 }
            // n = 6, score = 700
            //   ffd6                 | call                esi
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   8bd0                 | mov                 edx, eax
            //   8d8d58ffffff         | lea                 ecx, [ebp - 0xa8]
            //   ffd6                 | call                esi

    condition:
        7 of them and filesize < 1540096
}