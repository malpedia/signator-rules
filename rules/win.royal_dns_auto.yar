rule win_royal_dns_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.royal_dns."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.royal_dns"
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
        $sequence_0 = { 8d148580502500 8b0a 83e61f c1e606 03ce 8a4124 02c0 }
            // n = 7, score = 100
            //   8d148580502500       | lea                 edx, [eax*4 + 0x255080]
            //   8b0a                 | mov                 ecx, dword ptr [edx]
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   03ce                 | add                 ecx, esi
            //   8a4124               | mov                 al, byte ptr [ecx + 0x24]
            //   02c0                 | add                 al, al

        $sequence_1 = { 59 3bc1 0f87c8090000 ff248553b42400 33c0 838de8fdffffff 898594fdffff }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   3bc1                 | cmp                 eax, ecx
            //   0f87c8090000         | ja                  0x9ce
            //   ff248553b42400       | jmp                 dword ptr [eax*4 + 0x24b453]
            //   33c0                 | xor                 eax, eax
            //   838de8fdffffff       | or                  dword ptr [ebp - 0x218], 0xffffffff
            //   898594fdffff         | mov                 dword ptr [ebp - 0x26c], eax

        $sequence_2 = { 7e2f 8b5304 6800010000 52 8d8424e0010000 }
            // n = 5, score = 100
            //   7e2f                 | jle                 0x31
            //   8b5304               | mov                 edx, dword ptr [ebx + 4]
            //   6800010000           | push                0x100
            //   52                   | push                edx
            //   8d8424e0010000       | lea                 eax, [esp + 0x1e0]

        $sequence_3 = { 7491 53 56 e8???????? 83c408 85c0 }
            // n = 6, score = 100
            //   7491                 | je                  0xffffff93
            //   53                   | push                ebx
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax

        $sequence_4 = { 46 8955fc 85c0 7416 03d8 03d0 }
            // n = 6, score = 100
            //   46                   | inc                 esi
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   85c0                 | test                eax, eax
            //   7416                 | je                  0x18
            //   03d8                 | add                 ebx, eax
            //   03d0                 | add                 edx, eax

        $sequence_5 = { 56 8d95e8fdffff 68???????? 52 e8???????? 83c40c }
            // n = 6, score = 100
            //   56                   | push                esi
            //   8d95e8fdffff         | lea                 edx, [ebp - 0x218]
            //   68????????           |                     
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_6 = { 50 ff15???????? 8b8de4fdffff 8b35???????? 51 ffd6 8b95e0fdffff }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b8de4fdffff         | mov                 ecx, dword ptr [ebp - 0x21c]
            //   8b35????????         |                     
            //   51                   | push                ecx
            //   ffd6                 | call                esi
            //   8b95e0fdffff         | mov                 edx, dword ptr [ebp - 0x220]

        $sequence_7 = { 2bc2 898590fcffff 8b8d90fcffff 68???????? 41 }
            // n = 5, score = 100
            //   2bc2                 | sub                 eax, edx
            //   898590fcffff         | mov                 dword ptr [ebp - 0x370], eax
            //   8b8d90fcffff         | mov                 ecx, dword ptr [ebp - 0x370]
            //   68????????           |                     
            //   41                   | inc                 ecx

        $sequence_8 = { 8d8c05fcfeffff 88040a 8bd0 83e20f 8a141a 40 8811 }
            // n = 7, score = 100
            //   8d8c05fcfeffff       | lea                 ecx, [ebp + eax - 0x104]
            //   88040a               | mov                 byte ptr [edx + ecx], al
            //   8bd0                 | mov                 edx, eax
            //   83e20f               | and                 edx, 0xf
            //   8a141a               | mov                 dl, byte ptr [edx + ebx]
            //   40                   | inc                 eax
            //   8811                 | mov                 byte ptr [ecx], dl

        $sequence_9 = { 5e 885106 66c741073700 5b }
            // n = 4, score = 100
            //   5e                   | pop                 esi
            //   885106               | mov                 byte ptr [ecx + 6], dl
            //   66c741073700         | mov                 word ptr [ecx + 7], 0x37
            //   5b                   | pop                 ebx

    condition:
        7 of them and filesize < 204800
}