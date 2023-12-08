rule win_joao_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.joao."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.joao"
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
        $sequence_0 = { 8bce 897dfc e8???????? 837de810 c745fcffffffff 720c 8b45d4 }
            // n = 7, score = 400
            //   8bce                 | mov                 ecx, esi
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   e8????????           |                     
            //   837de810             | cmp                 dword ptr [ebp - 0x18], 0x10
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   720c                 | jb                  0xe
            //   8b45d4               | mov                 eax, dword ptr [ebp - 0x2c]

        $sequence_1 = { 8b4e08 2b0e c1f905 3bc8 }
            // n = 4, score = 400
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]
            //   2b0e                 | sub                 ecx, dword ptr [esi]
            //   c1f905               | sar                 ecx, 5
            //   3bc8                 | cmp                 ecx, eax

        $sequence_2 = { 8d4dd0 51 8bce 897dfc e8???????? }
            // n = 5, score = 400
            //   8d4dd0               | lea                 ecx, [ebp - 0x30]
            //   51                   | push                ecx
            //   8bce                 | mov                 ecx, esi
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   e8????????           |                     

        $sequence_3 = { 50 6a0f 68???????? e8???????? 8b5510 8d8df8feffff }
            // n = 6, score = 400
            //   50                   | push                eax
            //   6a0f                 | push                0xf
            //   68????????           |                     
            //   e8????????           |                     
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   8d8df8feffff         | lea                 ecx, [ebp - 0x108]

        $sequence_4 = { 8b4804 8b4c3138 c645ef01 4b }
            // n = 4, score = 400
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   8b4c3138             | mov                 ecx, dword ptr [ecx + esi + 0x38]
            //   c645ef01             | mov                 byte ptr [ebp - 0x11], 1
            //   4b                   | dec                 ebx

        $sequence_5 = { 8d45f8 50 8bce c745f809000000 897dfc e8???????? 8d4df8 }
            // n = 7, score = 400
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   8bce                 | mov                 ecx, esi
            //   c745f809000000       | mov                 dword ptr [ebp - 8], 9
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   e8????????           |                     
            //   8d4df8               | lea                 ecx, [ebp - 8]

        $sequence_6 = { e8???????? 8b4604 83e7e0 033e }
            // n = 4, score = 400
            //   e8????????           |                     
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   83e7e0               | and                 edi, 0xffffffe0
            //   033e                 | add                 edi, dword ptr [esi]

        $sequence_7 = { 8b4c3224 8b443220 c645fc03 85c9 7c15 7f04 }
            // n = 6, score = 400
            //   8b4c3224             | mov                 ecx, dword ptr [edx + esi + 0x24]
            //   8b443220             | mov                 eax, dword ptr [edx + esi + 0x20]
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3
            //   85c9                 | test                ecx, ecx
            //   7c15                 | jl                  0x17
            //   7f04                 | jg                  6

        $sequence_8 = { 8d4dd4 e8???????? 8d4dd0 51 8bce 897dfc e8???????? }
            // n = 7, score = 400
            //   8d4dd4               | lea                 ecx, [ebp - 0x2c]
            //   e8????????           |                     
            //   8d4dd0               | lea                 ecx, [ebp - 0x30]
            //   51                   | push                ecx
            //   8bce                 | mov                 ecx, esi
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   e8????????           |                     

        $sequence_9 = { 8b4e08 2b0e c1f905 3bc8 736a 8d7e0c 50 }
            // n = 7, score = 400
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]
            //   2b0e                 | sub                 ecx, dword ptr [esi]
            //   c1f905               | sar                 ecx, 5
            //   3bc8                 | cmp                 ecx, eax
            //   736a                 | jae                 0x6c
            //   8d7e0c               | lea                 edi, [esi + 0xc]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 2867200
}