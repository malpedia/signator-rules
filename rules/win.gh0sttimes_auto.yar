rule win_gh0sttimes_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.gh0sttimes."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gh0sttimes"
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
        $sequence_0 = { 6a01 8d4dec c645ec72 e8???????? 57 ff15???????? 5f }
            // n = 7, score = 800
            //   6a01                 | push                1
            //   8d4dec               | lea                 ecx, dword ptr [ebp - 0x14]
            //   c645ec72             | mov                 byte ptr [ebp - 0x14], 0x72
            //   e8????????           |                     
            //   57                   | push                edi
            //   ff15????????         |                     
            //   5f                   | pop                 edi

        $sequence_1 = { ff15???????? 6810040000 6860010000 8d8d8cf8ffff 51 }
            // n = 5, score = 800
            //   ff15????????         |                     
            //   6810040000           | push                0x410
            //   6860010000           | push                0x160
            //   8d8d8cf8ffff         | lea                 ecx, dword ptr [ebp - 0x774]
            //   51                   | push                ecx

        $sequence_2 = { 57 8d7e10 50 51 8d5df4 e8???????? 837e2800 }
            // n = 7, score = 800
            //   57                   | push                edi
            //   8d7e10               | lea                 edi, dword ptr [esi + 0x10]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   8d5df4               | lea                 ebx, dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   837e2800             | cmp                 dword ptr [esi + 0x28], 0

        $sequence_3 = { 53 8b1d???????? 56 57 8b7d08 c785f0fbffff00000000 }
            // n = 6, score = 800
            //   53                   | push                ebx
            //   8b1d????????         |                     
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   c785f0fbffff00000000     | mov    dword ptr [ebp - 0x410], 0

        $sequence_4 = { 50 c7431400000000 e8???????? 83c408 8b4df4 64890d00000000 }
            // n = 6, score = 800
            //   50                   | push                eax
            //   c7431400000000       | mov                 dword ptr [ebx + 0x14], 0
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx

        $sequence_5 = { c745fc00000000 e8???????? 894614 c7461800000000 8bc6 8b4df4 }
            // n = 6, score = 800
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   e8????????           |                     
            //   894614               | mov                 dword ptr [esi + 0x14], eax
            //   c7461800000000       | mov                 dword ptr [esi + 0x18], 0
            //   8bc6                 | mov                 eax, esi
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_6 = { 8d959cf9ffff 52 ff15???????? 8bf8 }
            // n = 4, score = 800
            //   8d959cf9ffff         | lea                 edx, dword ptr [ebp - 0x664]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax

        $sequence_7 = { 89941df2f9ffff e8???????? 8b9580f8ffff 83c40c }
            // n = 4, score = 800
            //   89941df2f9ffff       | mov                 dword ptr [ebp + ebx - 0x60e], edx
            //   e8????????           |                     
            //   8b9580f8ffff         | mov                 edx, dword ptr [ebp - 0x780]
            //   83c40c               | add                 esp, 0xc

        $sequence_8 = { 488b4c2430 488b03 48c1e807 c1e004 }
            // n = 4, score = 600
            //   488b4c2430           | dec                 eax
            //   488b03               | mov                 ecx, dword ptr [esp + 0x30]
            //   48c1e807             | dec                 eax
            //   c1e004               | add                 ecx, 0xaa4

        $sequence_9 = { 488b4c2430 41b8e3ffffff 8b4120 4123c0 }
            // n = 4, score = 600
            //   488b4c2430           | sub                 eax, ecx
            //   41b8e3ffffff         | mov                 ecx, 0x102
            //   8b4120               | sub                 ecx, eax
            //   4123c0               | dec                 eax

        $sequence_10 = { 488b4c2430 4881c1a40a0000 488b442430 488988700b0000 }
            // n = 4, score = 600
            //   488b4c2430           | mov                 ecx, dword ptr [esp + 0x30]
            //   4881c1a40a0000       | inc                 ecx
            //   488b442430           | mov                 eax, 0xffffffe3
            //   488988700b0000       | mov                 eax, dword ptr [ecx + 0x20]

        $sequence_11 = { 488b4c2430 488b03 48c1e809 c1e003 }
            // n = 4, score = 600
            //   488b4c2430           | dec                 eax
            //   488b03               | mov                 eax, dword ptr [esp + 0x30]
            //   48c1e809             | dec                 eax
            //   c1e003               | mov                 dword ptr [eax + 0xb58], ecx

        $sequence_12 = { 488b4c2430 4881c1bc000000 488b442430 488988400b0000 }
            // n = 4, score = 600
            //   488b4c2430           | mov                 eax, dword ptr [esp + 0x50]
            //   4881c1bc000000       | dec                 eax
            //   488b442430           | mov                 ecx, dword ptr [esp + 0x30]
            //   488988400b0000       | dec                 eax

        $sequence_13 = { 440fb7442440 44895c2438 89442430 894c2428 }
            // n = 4, score = 600
            //   440fb7442440         | inc                 esp
            //   44895c2438           | movzx               eax, word ptr [esp + 0x40]
            //   89442430             | inc                 esp
            //   894c2428             | mov                 dword ptr [esp + 0x38], ebx

        $sequence_14 = { 488b4c2428 488b442438 482bc1 b902010000 2bc8 488b842480000000 898888000000 }
            // n = 7, score = 600
            //   488b4c2428           | mov                 dword ptr [esp + 0x30], eax
            //   488b442438           | mov                 dword ptr [esp + 0x28], ecx
            //   482bc1               | dec                 eax
            //   b902010000           | mov                 ecx, dword ptr [esp + 0x28]
            //   2bc8                 | dec                 eax
            //   488b842480000000     | mov                 eax, dword ptr [esp + 0x38]
            //   898888000000         | dec                 eax

        $sequence_15 = { 488b4c2430 4881c1b0090000 488b442430 488988580b0000 }
            // n = 4, score = 600
            //   488b4c2430           | mov                 ecx, dword ptr [esp + 0x30]
            //   4881c1b0090000       | inc                 ecx
            //   488b442430           | mov                 eax, 0xffffffe3
            //   488988580b0000       | mov                 eax, dword ptr [ecx + 0x20]

    condition:
        7 of them and filesize < 548864
}