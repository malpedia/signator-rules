rule win_zebrocy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.zebrocy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zebrocy"
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
        $sequence_0 = { 014158 11515c e8???????? dc6360 }
            // n = 4, score = 100
            //   014158               | add                 dword ptr [ecx + 0x58], eax
            //   11515c               | adc                 dword ptr [ecx + 0x5c], edx
            //   e8????????           |                     
            //   dc6360               | fsub                qword ptr [ebx + 0x60]

        $sequence_1 = { 8bc6 33d2 66891478 8bc6 5f c3 8bff }
            // n = 7, score = 100
            //   8bc6                 | mov                 eax, esi
            //   33d2                 | xor                 edx, edx
            //   66891478             | mov                 word ptr [eax + edi*2], dx
            //   8bc6                 | mov                 eax, esi
            //   5f                   | pop                 edi
            //   c3                   | ret                 
            //   8bff                 | mov                 edi, edi

        $sequence_2 = { 0103 83c41c 5b 5e }
            // n = 4, score = 100
            //   0103                 | add                 dword ptr [ebx], eax
            //   83c41c               | add                 esp, 0x1c
            //   5b                   | pop                 ebx
            //   5e                   | pop                 esi

        $sequence_3 = { 83c438 68581b0000 ff15???????? 83bd00f7ffff08 8b85ecf6ffff 7306 8d85ecf6ffff }
            // n = 7, score = 100
            //   83c438               | add                 esp, 0x38
            //   68581b0000           | push                0x1b58
            //   ff15????????         |                     
            //   83bd00f7ffff08       | cmp                 dword ptr [ebp - 0x900], 8
            //   8b85ecf6ffff         | mov                 eax, dword ptr [ebp - 0x914]
            //   7306                 | jae                 8
            //   8d85ecf6ffff         | lea                 eax, [ebp - 0x914]

        $sequence_4 = { 8b7508 837e0800 7610 8b4608 8d808c994200 fe08 }
            // n = 6, score = 100
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   837e0800             | cmp                 dword ptr [esi + 8], 0
            //   7610                 | jbe                 0x12
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   8d808c994200         | lea                 eax, [eax + 0x42998c]
            //   fe08                 | dec                 byte ptr [eax]

        $sequence_5 = { 0110 8b7dd4 ba???????? 89470c }
            // n = 4, score = 100
            //   0110                 | add                 dword ptr [eax], edx
            //   8b7dd4               | mov                 edi, dword ptr [ebp - 0x2c]
            //   ba????????           |                     
            //   89470c               | mov                 dword ptr [edi + 0xc], eax

        $sequence_6 = { 0103 8b0e ba???????? e8???????? }
            // n = 4, score = 100
            //   0103                 | add                 dword ptr [ebx], eax
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   ba????????           |                     
            //   e8????????           |                     

        $sequence_7 = { 8b441a20 85c9 7f0d 7c05 83f801 7706 }
            // n = 6, score = 100
            //   8b441a20             | mov                 eax, dword ptr [edx + ebx + 0x20]
            //   85c9                 | test                ecx, ecx
            //   7f0d                 | jg                  0xf
            //   7c05                 | jl                  7
            //   83f801               | cmp                 eax, 1
            //   7706                 | ja                  8

        $sequence_8 = { 0102 8b45d4 89500c 89c1 }
            // n = 4, score = 100
            //   0102                 | add                 dword ptr [edx], eax
            //   8b45d4               | mov                 eax, dword ptr [ebp - 0x2c]
            //   89500c               | mov                 dword ptr [eax + 0xc], edx
            //   89c1                 | mov                 ecx, eax

        $sequence_9 = { 014150 8b550c 115154 014158 }
            // n = 4, score = 100
            //   014150               | add                 dword ptr [ecx + 0x50], eax
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   115154               | adc                 dword ptr [ecx + 0x54], edx
            //   014158               | add                 dword ptr [ecx + 0x58], eax

        $sequence_10 = { 0f8553010000 837de400 7c5d 7f04 85f6 }
            // n = 5, score = 100
            //   0f8553010000         | jne                 0x159
            //   837de400             | cmp                 dword ptr [ebp - 0x1c], 0
            //   7c5d                 | jl                  0x5f
            //   7f04                 | jg                  6
            //   85f6                 | test                esi, esi

        $sequence_11 = { 0103 31d2 85ff 8b03 }
            // n = 4, score = 100
            //   0103                 | add                 dword ptr [ebx], eax
            //   31d2                 | xor                 edx, edx
            //   85ff                 | test                edi, edi
            //   8b03                 | mov                 eax, dword ptr [ebx]

        $sequence_12 = { 7303 8d45b8 8b4dc8 03c8 8bc6 83fa10 }
            // n = 6, score = 100
            //   7303                 | jae                 5
            //   8d45b8               | lea                 eax, [ebp - 0x48]
            //   8b4dc8               | mov                 ecx, dword ptr [ebp - 0x38]
            //   03c8                 | add                 ecx, eax
            //   8bc6                 | mov                 eax, esi
            //   83fa10               | cmp                 edx, 0x10

        $sequence_13 = { 68???????? 6888000800 ff15???????? 8bf0 85f6 }
            // n = 5, score = 100
            //   68????????           |                     
            //   6888000800           | push                0x80088
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi

        $sequence_14 = { 0110 5e 5f 5d }
            // n = 4, score = 100
            //   0110                 | add                 dword ptr [eax], edx
            //   5e                   | pop                 esi
            //   5f                   | pop                 edi
            //   5d                   | pop                 ebp

        $sequence_15 = { 3bc1 0f87c8090000 ff2485689c4100 33c0 838de8fdffffff }
            // n = 5, score = 100
            //   3bc1                 | cmp                 eax, ecx
            //   0f87c8090000         | ja                  0x9ce
            //   ff2485689c4100       | jmp                 dword ptr [eax*4 + 0x419c68]
            //   33c0                 | xor                 eax, eax
            //   838de8fdffffff       | or                  dword ptr [ebp - 0x218], 0xffffffff

    condition:
        7 of them and filesize < 393216
}