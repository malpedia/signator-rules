rule win_phandoor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.phandoor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phandoor"
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
        $sequence_0 = { 8955f0 8ad0 2255ff 32d9 }
            // n = 4, score = 800
            //   8955f0               | mov                 dword ptr [ebp - 0x10], edx
            //   8ad0                 | mov                 dl, al
            //   2255ff               | and                 dl, byte ptr [ebp - 1]
            //   32d9                 | xor                 bl, cl

        $sequence_1 = { 0f8400010000 57 8d4900 8d45f8 50 895df8 }
            // n = 6, score = 800
            //   0f8400010000         | je                  0x106
            //   57                   | push                edi
            //   8d4900               | lea                 ecx, [ecx]
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   895df8               | mov                 dword ptr [ebp - 8], ebx

        $sequence_2 = { 0fb6843e94010000 50 b9???????? e8???????? }
            // n = 4, score = 800
            //   0fb6843e94010000     | movzx               eax, byte ptr [esi + edi + 0x194]
            //   50                   | push                eax
            //   b9????????           |                     
            //   e8????????           |                     

        $sequence_3 = { 833d????????00 745e 833d????????00 7455 833d????????00 744c }
            // n = 6, score = 800
            //   833d????????00       |                     
            //   745e                 | je                  0x60
            //   833d????????00       |                     
            //   7455                 | je                  0x57
            //   833d????????00       |                     
            //   744c                 | je                  0x4e

        $sequence_4 = { 0f84c7010000 833d????????00 0f84ba010000 833d????????00 0f84ad010000 833d????????00 0f84a0010000 }
            // n = 7, score = 800
            //   0f84c7010000         | je                  0x1cd
            //   833d????????00       |                     
            //   0f84ba010000         | je                  0x1c0
            //   833d????????00       |                     
            //   0f84ad010000         | je                  0x1b3
            //   833d????????00       |                     
            //   0f84a0010000         | je                  0x1a6

        $sequence_5 = { 8b8eb8010000 890d???????? 8b96bc010000 8915???????? 33ff }
            // n = 5, score = 800
            //   8b8eb8010000         | mov                 ecx, dword ptr [esi + 0x1b8]
            //   890d????????         |                     
            //   8b96bc010000         | mov                 edx, dword ptr [esi + 0x1bc]
            //   8915????????         |                     
            //   33ff                 | xor                 edi, edi

        $sequence_6 = { 50 57 ffd6 833d????????00 a3???????? 7463 833d????????00 }
            // n = 7, score = 800
            //   50                   | push                eax
            //   57                   | push                edi
            //   ffd6                 | call                esi
            //   833d????????00       |                     
            //   a3????????           |                     
            //   7463                 | je                  0x65
            //   833d????????00       |                     

        $sequence_7 = { eb74 8b96b0010000 8915???????? 8b86b4010000 a3???????? 8b8eb8010000 }
            // n = 6, score = 800
            //   eb74                 | jmp                 0x76
            //   8b96b0010000         | mov                 edx, dword ptr [esi + 0x1b0]
            //   8915????????         |                     
            //   8b86b4010000         | mov                 eax, dword ptr [esi + 0x1b4]
            //   a3????????           |                     
            //   8b8eb8010000         | mov                 ecx, dword ptr [esi + 0x1b8]

        $sequence_8 = { 57 68???????? 50 c705????????03000000 ffd6 }
            // n = 5, score = 500
            //   57                   | push                edi
            //   68????????           |                     
            //   50                   | push                eax
            //   c705????????03000000     |     
            //   ffd6                 | call                esi

        $sequence_9 = { 740b 8a4601 46 43 }
            // n = 4, score = 500
            //   740b                 | je                  0xd
            //   8a4601               | mov                 al, byte ptr [esi + 1]
            //   46                   | inc                 esi
            //   43                   | inc                 ebx

        $sequence_10 = { 57 6a12 51 ff15???????? }
            // n = 4, score = 500
            //   57                   | push                edi
            //   6a12                 | push                0x12
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_11 = { 33c9 c645fc02 7705 83f8ff }
            // n = 4, score = 500
            //   33c9                 | xor                 ecx, ecx
            //   c645fc02             | mov                 byte ptr [ebp - 4], 2
            //   7705                 | ja                  7
            //   83f8ff               | cmp                 eax, -1

        $sequence_12 = { 52 ff15???????? 85c0 743f 894608 }
            // n = 5, score = 500
            //   52                   | push                edx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   743f                 | je                  0x41
            //   894608               | mov                 dword ptr [esi + 8], eax

        $sequence_13 = { 750b c60300 50 43 }
            // n = 4, score = 500
            //   750b                 | jne                 0xd
            //   c60300               | mov                 byte ptr [ebx], 0
            //   50                   | push                eax
            //   43                   | inc                 ebx

        $sequence_14 = { 3bcf 7e71 3b4e04 7c30 }
            // n = 4, score = 500
            //   3bcf                 | cmp                 ecx, edi
            //   7e71                 | jle                 0x73
            //   3b4e04               | cmp                 ecx, dword ptr [esi + 4]
            //   7c30                 | jl                  0x32

        $sequence_15 = { 0fb74d10 8b550c 6a01 51 }
            // n = 4, score = 500
            //   0fb74d10             | movzx               ecx, word ptr [ebp + 0x10]
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   6a01                 | push                1
            //   51                   | push                ecx

    condition:
        7 of them and filesize < 2124800
}