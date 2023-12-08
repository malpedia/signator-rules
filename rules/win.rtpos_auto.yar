rule win_rtpos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.rtpos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rtpos"
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
        $sequence_0 = { 68a8040000 8b45ec 50 e8???????? 83c408 c3 8b542408 }
            // n = 7, score = 100
            //   68a8040000           | push                0x4a8
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   c3                   | ret                 
            //   8b542408             | mov                 edx, dword ptr [esp + 8]

        $sequence_1 = { 83e908 8d7608 660fd60f 8d7f08 8b048d74b44000 }
            // n = 5, score = 100
            //   83e908               | sub                 ecx, 8
            //   8d7608               | lea                 esi, [esi + 8]
            //   660fd60f             | movq                qword ptr [edi], xmm1
            //   8d7f08               | lea                 edi, [edi + 8]
            //   8b048d74b44000       | mov                 eax, dword ptr [ecx*4 + 0x40b474]

        $sequence_2 = { 8b0cc5c4ae4200 894de4 85c9 7455 }
            // n = 4, score = 100
            //   8b0cc5c4ae4200       | mov                 ecx, dword ptr [eax*8 + 0x42aec4]
            //   894de4               | mov                 dword ptr [ebp - 0x1c], ecx
            //   85c9                 | test                ecx, ecx
            //   7455                 | je                  0x57

        $sequence_3 = { 7619 8b4dd4 51 ff15???????? }
            // n = 4, score = 100
            //   7619                 | jbe                 0x1b
            //   8b4dd4               | mov                 ecx, dword ptr [ebp - 0x2c]
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_4 = { 8d45d8 50 6a00 8b4dd4 51 }
            // n = 5, score = 100
            //   8d45d8               | lea                 eax, [ebp - 0x28]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   8b4dd4               | mov                 ecx, dword ptr [ebp - 0x2c]
            //   51                   | push                ecx

        $sequence_5 = { 85c0 752c 6a00 68???????? 68???????? 6a02 68???????? }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   752c                 | jne                 0x2e
            //   6a00                 | push                0
            //   68????????           |                     
            //   68????????           |                     
            //   6a02                 | push                2
            //   68????????           |                     

        $sequence_6 = { 8bec 53 8b5d08 33c9 57 33c0 8d3c9d5c654300 }
            // n = 7, score = 100
            //   8bec                 | mov                 ebp, esp
            //   53                   | push                ebx
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   33c9                 | xor                 ecx, ecx
            //   57                   | push                edi
            //   33c0                 | xor                 eax, eax
            //   8d3c9d5c654300       | lea                 edi, [ebx*4 + 0x43655c]

        $sequence_7 = { 33c5 8945fc c745d800000000 c745dc00000000 33c0 }
            // n = 5, score = 100
            //   33c5                 | xor                 eax, ebp
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   c745d800000000       | mov                 dword ptr [ebp - 0x28], 0
            //   c745dc00000000       | mov                 dword ptr [ebp - 0x24], 0
            //   33c0                 | xor                 eax, eax

        $sequence_8 = { 2b45c4 3b45f0 7619 8b4dd4 51 ff15???????? }
            // n = 6, score = 100
            //   2b45c4               | sub                 eax, dword ptr [ebp - 0x3c]
            //   3b45f0               | cmp                 eax, dword ptr [ebp - 0x10]
            //   7619                 | jbe                 0x1b
            //   8b4dd4               | mov                 ecx, dword ptr [ebp - 0x2c]
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_9 = { 6bc030 03048db86a4300 50 ff15???????? 5d c3 }
            // n = 6, score = 100
            //   6bc030               | imul                eax, eax, 0x30
            //   03048db86a4300       | add                 eax, dword ptr [ecx*4 + 0x436ab8]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   5d                   | pop                 ebp
            //   c3                   | ret                 

    condition:
        7 of them and filesize < 507904
}