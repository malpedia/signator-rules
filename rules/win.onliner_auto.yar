rule win_onliner_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.onliner."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.onliner"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
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
        $sequence_0 = { 0f8274ffffff 6683ff04 0f8596000000 33ff 8d45e4 668b55ee c1e202 }
            // n = 7, score = 100
            //   0f8274ffffff         | jb                  0xffffff7a
            //   6683ff04             | cmp                 di, 4
            //   0f8596000000         | jne                 0x9c
            //   33ff                 | xor                 edi, edi
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   668b55ee             | mov                 dx, word ptr [ebp - 0x12]
            //   c1e202               | shl                 edx, 2

        $sequence_1 = { 8d8db4feffff 8bd3 8bc6 8b38 ff570c 8b85b4feffff 5a }
            // n = 7, score = 100
            //   8d8db4feffff         | lea                 ecx, [ebp - 0x14c]
            //   8bd3                 | mov                 edx, ebx
            //   8bc6                 | mov                 eax, esi
            //   8b38                 | mov                 edi, dword ptr [eax]
            //   ff570c               | call                dword ptr [edi + 0xc]
            //   8b85b4feffff         | mov                 eax, dword ptr [ebp - 0x14c]
            //   5a                   | pop                 edx

        $sequence_2 = { 85c0 7405 3b50fc 7205 e8???????? 42 8d4410ff }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   7405                 | je                  7
            //   3b50fc               | cmp                 edx, dword ptr [eax - 4]
            //   7205                 | jb                  7
            //   e8????????           |                     
            //   42                   | inc                 edx
            //   8d4410ff             | lea                 eax, [eax + edx - 1]

        $sequence_3 = { 50 6a00 8bc3 e8???????? 50 ff15???????? }
            // n = 6, score = 100
            //   50                   | push                eax
            //   6a00                 | push                0
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_4 = { 3b45e4 0f84ab000000 ff45e4 807dee00 742c 8b55e4 2bd0 }
            // n = 7, score = 100
            //   3b45e4               | cmp                 eax, dword ptr [ebp - 0x1c]
            //   0f84ab000000         | je                  0xb1
            //   ff45e4               | inc                 dword ptr [ebp - 0x1c]
            //   807dee00             | cmp                 byte ptr [ebp - 0x12], 0
            //   742c                 | je                  0x2e
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]
            //   2bd0                 | sub                 edx, eax

        $sequence_5 = { 3345fc 03c6 0345cc 05c8fbd3e7 ba14000000 e8???????? 03c7 }
            // n = 7, score = 100
            //   3345fc               | xor                 eax, dword ptr [ebp - 4]
            //   03c6                 | add                 eax, esi
            //   0345cc               | add                 eax, dword ptr [ebp - 0x34]
            //   05c8fbd3e7           | add                 eax, 0xe7d3fbc8
            //   ba14000000           | mov                 edx, 0x14
            //   e8????????           |                     
            //   03c7                 | add                 eax, edi

        $sequence_6 = { 8bda 8bf0 8bc3 ba02000000 e8???????? 8bc3 e8???????? }
            // n = 7, score = 100
            //   8bda                 | mov                 ebx, edx
            //   8bf0                 | mov                 esi, eax
            //   8bc3                 | mov                 eax, ebx
            //   ba02000000           | mov                 edx, 2
            //   e8????????           |                     
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     

        $sequence_7 = { 33c0 8945ec 837df000 7426 83caff 8b45f8 }
            // n = 6, score = 100
            //   33c0                 | xor                 eax, eax
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   837df000             | cmp                 dword ptr [ebp - 0x10], 0
            //   7426                 | je                  0x28
            //   83caff               | or                  edx, 0xffffffff
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

        $sequence_8 = { 3bc3 7c07 807c1eff20 74f4 57 b9ffffff7f 8bd3 }
            // n = 7, score = 100
            //   3bc3                 | cmp                 eax, ebx
            //   7c07                 | jl                  9
            //   807c1eff20           | cmp                 byte ptr [esi + ebx - 1], 0x20
            //   74f4                 | je                  0xfffffff6
            //   57                   | push                edi
            //   b9ffffff7f           | mov                 ecx, 0x7fffffff
            //   8bd3                 | mov                 edx, ebx

        $sequence_9 = { 8b45fc 8b88d0010000 ba02000000 8b45fc 8b18 ff534c ff75e4 }
            // n = 7, score = 100
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b88d0010000         | mov                 ecx, dword ptr [eax + 0x1d0]
            //   ba02000000           | mov                 edx, 2
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b18                 | mov                 ebx, dword ptr [eax]
            //   ff534c               | call                dword ptr [ebx + 0x4c]
            //   ff75e4               | push                dword ptr [ebp - 0x1c]

    condition:
        7 of them and filesize < 1736704
}