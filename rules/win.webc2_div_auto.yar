rule win_webc2_div_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.webc2_div."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_div"
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
        $sequence_0 = { 8975f8 f3ab 66ab aa 8d45f8 }
            // n = 5, score = 100
            //   8975f8               | mov                 dword ptr [ebp - 8], esi
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8d45f8               | lea                 eax, [ebp - 8]

        $sequence_1 = { 8b542410 8b35???????? 52 ffd6 6801000080 ffd6 }
            // n = 6, score = 100
            //   8b542410             | mov                 edx, dword ptr [esp + 0x10]
            //   8b35????????         |                     
            //   52                   | push                edx
            //   ffd6                 | call                esi
            //   6801000080           | push                0x80000001
            //   ffd6                 | call                esi

        $sequence_2 = { 5f e9???????? 6a3c 51 e9???????? 85c0 0f842c010000 }
            // n = 7, score = 100
            //   5f                   | pop                 edi
            //   e9????????           |                     
            //   6a3c                 | push                0x3c
            //   51                   | push                ecx
            //   e9????????           |                     
            //   85c0                 | test                eax, eax
            //   0f842c010000         | je                  0x132

        $sequence_3 = { 894508 7509 57 ff15???????? eb54 a0???????? b9ff000000 }
            // n = 7, score = 100
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   7509                 | jne                 0xb
            //   57                   | push                edi
            //   ff15????????         |                     
            //   eb54                 | jmp                 0x56
            //   a0????????           |                     
            //   b9ff000000           | mov                 ecx, 0xff

        $sequence_4 = { 6a00 ff15???????? 8b54240c 8d4c2414 51 52 }
            // n = 6, score = 100
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8b54240c             | mov                 edx, dword ptr [esp + 0xc]
            //   8d4c2414             | lea                 ecx, [esp + 0x14]
            //   51                   | push                ecx
            //   52                   | push                edx

        $sequence_5 = { 3c7a 7f08 0fbed0 83ea61 eb21 3c2e 7c0f }
            // n = 7, score = 100
            //   3c7a                 | cmp                 al, 0x7a
            //   7f08                 | jg                  0xa
            //   0fbed0               | movsx               edx, al
            //   83ea61               | sub                 edx, 0x61
            //   eb21                 | jmp                 0x23
            //   3c2e                 | cmp                 al, 0x2e
            //   7c0f                 | jl                  0x11

        $sequence_6 = { 7512 ffd6 ff75fc ffd6 53 e8???????? 59 }
            // n = 7, score = 100
            //   7512                 | jne                 0x14
            //   ffd6                 | call                esi
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ffd6                 | call                esi
            //   53                   | push                ebx
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_7 = { 8b35???????? 6a3c ff74241c ffd6 59 }
            // n = 5, score = 100
            //   8b35????????         |                     
            //   6a3c                 | push                0x3c
            //   ff74241c             | push                dword ptr [esp + 0x1c]
            //   ffd6                 | call                esi
            //   59                   | pop                 ecx

        $sequence_8 = { aa 8d45f8 50 8d85ecf9ffff 6800040000 50 ff7508 }
            // n = 7, score = 100
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   8d85ecf9ffff         | lea                 eax, [ebp - 0x614]
            //   6800040000           | push                0x400
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_9 = { 8ac8 80c161 eb1a 83f826 7f0b }
            // n = 5, score = 100
            //   8ac8                 | mov                 cl, al
            //   80c161               | add                 cl, 0x61
            //   eb1a                 | jmp                 0x1c
            //   83f826               | cmp                 eax, 0x26
            //   7f0b                 | jg                  0xd

    condition:
        7 of them and filesize < 32768
}