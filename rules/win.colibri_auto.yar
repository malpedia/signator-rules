rule win_colibri_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.colibri."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.colibri"
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
        $sequence_0 = { 6a02 59 e8???????? bab3e0cca3 8bc8 e8???????? ffd0 }
            // n = 7, score = 100
            //   6a02                 | push                2
            //   59                   | pop                 ecx
            //   e8????????           |                     
            //   bab3e0cca3           | mov                 edx, 0xa3cce0b3
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   ffd0                 | call                eax

        $sequence_1 = { e8???????? 83c410 8d8578f9ffff 33ff 6804010000 50 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8d8578f9ffff         | lea                 eax, [ebp - 0x688]
            //   33ff                 | xor                 edi, edi
            //   6804010000           | push                0x104
            //   50                   | push                eax

        $sequence_2 = { ffd0 a1???????? 83c414 8bcb 8d144502000000 e8???????? 8d45e8 }
            // n = 7, score = 100
            //   ffd0                 | call                eax
            //   a1????????           |                     
            //   83c414               | add                 esp, 0x14
            //   8bcb                 | mov                 ecx, ebx
            //   8d144502000000       | lea                 edx, [eax*2 + 2]
            //   e8????????           |                     
            //   8d45e8               | lea                 eax, [ebp - 0x18]

        $sequence_3 = { 8d4d90 8365ac00 894594 8d8568f9ffff 894598 8b45fc 8945b4 }
            // n = 7, score = 100
            //   8d4d90               | lea                 ecx, [ebp - 0x70]
            //   8365ac00             | and                 dword ptr [ebp - 0x54], 0
            //   894594               | mov                 dword ptr [ebp - 0x6c], eax
            //   8d8568f9ffff         | lea                 eax, [ebp - 0x698]
            //   894598               | mov                 dword ptr [ebp - 0x68], eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8945b4               | mov                 dword ptr [ebp - 0x4c], eax

        $sequence_4 = { 85c0 0f8486020000 33c9 8d442410 51 51 50 }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   0f8486020000         | je                  0x28c
            //   33c9                 | xor                 ecx, ecx
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   50                   | push                eax

        $sequence_5 = { 85c0 7409 837df800 7403 }
            // n = 4, score = 100
            //   85c0                 | test                eax, eax
            //   7409                 | je                  0xb
            //   837df800             | cmp                 dword ptr [ebp - 8], 0
            //   7403                 | je                  5

        $sequence_6 = { 8b75f8 33c0 668945d0 8d45e8 }
            // n = 4, score = 100
            //   8b75f8               | mov                 esi, dword ptr [ebp - 8]
            //   33c0                 | xor                 eax, eax
            //   668945d0             | mov                 word ptr [ebp - 0x30], ax
            //   8d45e8               | lea                 eax, [ebp - 0x18]

        $sequence_7 = { 59 a3???????? e8???????? ba49f6fd69 8bc8 e8???????? ffd0 }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   a3????????           |                     
            //   e8????????           |                     
            //   ba49f6fd69           | mov                 edx, 0x69fdf649
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   ffd0                 | call                eax

        $sequence_8 = { 85c0 0f848d000000 8d8590fdffff 50 53 8d8580fbffff 50 }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   0f848d000000         | je                  0x93
            //   8d8590fdffff         | lea                 eax, [ebp - 0x270]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   8d8580fbffff         | lea                 eax, [ebp - 0x480]
            //   50                   | push                eax

        $sequence_9 = { 57 8d0c4502000000 e8???????? 83ec10 8945f0 be???????? 8bfc }
            // n = 7, score = 100
            //   57                   | push                edi
            //   8d0c4502000000       | lea                 ecx, [eax*2 + 2]
            //   e8????????           |                     
            //   83ec10               | sub                 esp, 0x10
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   be????????           |                     
            //   8bfc                 | mov                 edi, esp

    condition:
        7 of them and filesize < 51200
}