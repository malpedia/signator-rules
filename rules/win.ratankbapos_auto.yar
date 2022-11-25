rule win_ratankbapos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.ratankbapos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ratankbapos"
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
        $sequence_0 = { 8b45e0 8b480c c701ffffffff 8b4510 0345fc }
            // n = 5, score = 300
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   8b480c               | mov                 ecx, dword ptr [eax + 0xc]
            //   c701ffffffff         | mov                 dword ptr [ecx], 0xffffffff
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   0345fc               | add                 eax, dword ptr [ebp - 4]

        $sequence_1 = { a1???????? 8945f8 837df800 7471 8d4df4 51 }
            // n = 6, score = 300
            //   a1????????           |                     
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   837df800             | cmp                 dword ptr [ebp - 8], 0
            //   7471                 | je                  0x73
            //   8d4df4               | lea                 ecx, [ebp - 0xc]
            //   51                   | push                ecx

        $sequence_2 = { e8???????? 83c408 8945e4 c745fc00000000 8d4dfc 51 }
            // n = 6, score = 300
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   8d4dfc               | lea                 ecx, [ebp - 4]
            //   51                   | push                ecx

        $sequence_3 = { 89951cfdffff 83bd1cfdffff00 0f8403010000 8b851cfdffff 83780400 7473 8b8d1cfdffff }
            // n = 7, score = 300
            //   89951cfdffff         | mov                 dword ptr [ebp - 0x2e4], edx
            //   83bd1cfdffff00       | cmp                 dword ptr [ebp - 0x2e4], 0
            //   0f8403010000         | je                  0x109
            //   8b851cfdffff         | mov                 eax, dword ptr [ebp - 0x2e4]
            //   83780400             | cmp                 dword ptr [eax + 4], 0
            //   7473                 | je                  0x75
            //   8b8d1cfdffff         | mov                 ecx, dword ptr [ebp - 0x2e4]

        $sequence_4 = { f7460c0c010000 754e 53 57 8d3c8534490110 833f00 bb00100000 }
            // n = 7, score = 300
            //   f7460c0c010000       | test                dword ptr [esi + 0xc], 0x10c
            //   754e                 | jne                 0x50
            //   53                   | push                ebx
            //   57                   | push                edi
            //   8d3c8534490110       | lea                 edi, [eax*4 + 0x10014934]
            //   833f00               | cmp                 dword ptr [edi], 0
            //   bb00100000           | mov                 ebx, 0x1000

        $sequence_5 = { ff15???????? c745fc00000000 8b55d0 8955c8 8b45c8 33c9 }
            // n = 6, score = 300
            //   ff15????????         |                     
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   8b55d0               | mov                 edx, dword ptr [ebp - 0x30]
            //   8955c8               | mov                 dword ptr [ebp - 0x38], edx
            //   8b45c8               | mov                 eax, dword ptr [ebp - 0x38]
            //   33c9                 | xor                 ecx, ecx

        $sequence_6 = { 8945c8 837dc800 7502 eb14 8b4dec }
            // n = 5, score = 300
            //   8945c8               | mov                 dword ptr [ebp - 0x38], eax
            //   837dc800             | cmp                 dword ptr [ebp - 0x38], 0
            //   7502                 | jne                 4
            //   eb14                 | jmp                 0x16
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]

        $sequence_7 = { 56 52 e8???????? 8d44244c 83c424 33d2 }
            // n = 6, score = 300
            //   56                   | push                esi
            //   52                   | push                edx
            //   e8????????           |                     
            //   8d44244c             | lea                 eax, [esp + 0x4c]
            //   83c424               | add                 esp, 0x24
            //   33d2                 | xor                 edx, edx

        $sequence_8 = { 7405 e9???????? e9???????? 8b4de4 3b4de8 }
            // n = 5, score = 300
            //   7405                 | je                  7
            //   e9????????           |                     
            //   e9????????           |                     
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]
            //   3b4de8               | cmp                 ecx, dword ptr [ebp - 0x18]

        $sequence_9 = { e8???????? 83c408 25ff000000 8b8d1cfdffff 8b510c }
            // n = 5, score = 300
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   25ff000000           | and                 eax, 0xff
            //   8b8d1cfdffff         | mov                 ecx, dword ptr [ebp - 0x2e4]
            //   8b510c               | mov                 edx, dword ptr [ecx + 0xc]

    condition:
        7 of them and filesize < 327680
}