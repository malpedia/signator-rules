rule win_dharma_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.dharma."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dharma"
        malpedia_rule_date = "20220405"
        malpedia_hash = "ecd38294bd47d5589be5cd5490dc8bb4804afc2a"
        malpedia_version = ""
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
        $sequence_0 = { 8b0c95b8b74000 81e1ff000000 33c1 8b55fc 330495b8d44000 8b4df4 894120 }
            // n = 7, score = 100
            //   8b0c95b8b74000       | mov                 ecx, dword ptr [edx*4 + 0x40b7b8]
            //   81e1ff000000         | and                 ecx, 0xff
            //   33c1                 | xor                 eax, ecx
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   330495b8d44000       | xor                 eax, dword ptr [edx*4 + 0x40d4b8]
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   894120               | mov                 dword ptr [ecx + 0x20], eax

        $sequence_1 = { 83bd90feffff3c 0f8da6000000 8b8d98feffff c1e105 8b9598feffff c1ea1b 0bca }
            // n = 7, score = 100
            //   83bd90feffff3c       | cmp                 dword ptr [ebp - 0x170], 0x3c
            //   0f8da6000000         | jge                 0xac
            //   8b8d98feffff         | mov                 ecx, dword ptr [ebp - 0x168]
            //   c1e105               | shl                 ecx, 5
            //   8b9598feffff         | mov                 edx, dword ptr [ebp - 0x168]
            //   c1ea1b               | shr                 edx, 0x1b
            //   0bca                 | or                  ecx, edx

        $sequence_2 = { 894128 8b5508 52 e8???????? 8b45f8 }
            // n = 5, score = 100
            //   894128               | mov                 dword ptr [ecx + 0x28], eax
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   52                   | push                edx
            //   e8????????           |                     
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

        $sequence_3 = { 3b4df4 0f83ad000000 8b55f0 c1e205 8b45ec 837c100401 }
            // n = 6, score = 100
            //   3b4df4               | cmp                 ecx, dword ptr [ebp - 0xc]
            //   0f83ad000000         | jae                 0xb3
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   c1e205               | shl                 edx, 5
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   837c100401           | cmp                 dword ptr [eax + edx + 4], 1

        $sequence_4 = { 8b450c 8b480c 8d1451 52 8b45e8 8b480c }
            // n = 6, score = 100
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8b480c               | mov                 ecx, dword ptr [eax + 0xc]
            //   8d1451               | lea                 edx, dword ptr [ecx + edx*2]
            //   52                   | push                edx
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   8b480c               | mov                 ecx, dword ptr [eax + 0xc]

        $sequence_5 = { 8981c0000000 6a02 6880000000 68???????? 68???????? e8???????? }
            // n = 6, score = 100
            //   8981c0000000         | mov                 dword ptr [ecx + 0xc0], eax
            //   6a02                 | push                2
            //   6880000000           | push                0x80
            //   68????????           |                     
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_6 = { 894de4 6a04 8d55fc 52 8b45e4 }
            // n = 5, score = 100
            //   894de4               | mov                 dword ptr [ebp - 0x1c], ecx
            //   6a04                 | push                4
            //   8d55fc               | lea                 edx, dword ptr [ebp - 4]
            //   52                   | push                edx
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]

        $sequence_7 = { 51 e8???????? 85c0 0f8477010000 837de400 0f8c6d010000 6a03 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f8477010000         | je                  0x17d
            //   837de400             | cmp                 dword ptr [ebp - 0x1c], 0
            //   0f8c6d010000         | jl                  0x173
            //   6a03                 | push                3

        $sequence_8 = { 51 e8???????? 83c40c 8b55c8 52 e8???????? 83c404 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8b55c8               | mov                 edx, dword ptr [ebp - 0x38]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_9 = { 8b5510 3bf7 7429 83fa00 7424 8d4416ff 3bf7 }
            // n = 7, score = 100
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   3bf7                 | cmp                 esi, edi
            //   7429                 | je                  0x2b
            //   83fa00               | cmp                 edx, 0
            //   7424                 | je                  0x26
            //   8d4416ff             | lea                 eax, dword ptr [esi + edx - 1]
            //   3bf7                 | cmp                 esi, edi

    condition:
        7 of them and filesize < 204800
}