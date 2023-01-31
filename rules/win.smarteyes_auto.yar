rule win_smarteyes_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.smarteyes."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.smarteyes"
        malpedia_rule_date = "20230124"
        malpedia_hash = "2ee0eebba83dce3d019a90519f2f972c0fcf9686"
        malpedia_version = "20230125"
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
        $sequence_0 = { 85c0 7538 68???????? 8d85e8feffff 50 }
            // n = 5, score = 100
            //   85c0                 | test                eax, eax
            //   7538                 | jne                 0x3a
            //   68????????           |                     
            //   8d85e8feffff         | lea                 eax, [ebp - 0x118]
            //   50                   | push                eax

        $sequence_1 = { 33c0 e9???????? 8d85ccfdffff 50 8d85d4fdffff 50 6a00 }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   8d85ccfdffff         | lea                 eax, [ebp - 0x234]
            //   50                   | push                eax
            //   8d85d4fdffff         | lea                 eax, [ebp - 0x22c]
            //   50                   | push                eax
            //   6a00                 | push                0

        $sequence_2 = { a5 e8???????? 59 59 85c0 7505 8b4508 }
            // n = 7, score = 100
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_3 = { 8b85c4000000 a900400000 7407 68???????? eb29 84c0 7907 }
            // n = 7, score = 100
            //   8b85c4000000         | mov                 eax, dword ptr [ebp + 0xc4]
            //   a900400000           | test                eax, 0x4000
            //   7407                 | je                  9
            //   68????????           |                     
            //   eb29                 | jmp                 0x2b
            //   84c0                 | test                al, al
            //   7907                 | jns                 9

        $sequence_4 = { 85c0 750e 8d85e8feffff 50 68???????? eb1b 8d8de8feffff }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   750e                 | jne                 0x10
            //   8d85e8feffff         | lea                 eax, [ebp - 0x118]
            //   50                   | push                eax
            //   68????????           |                     
            //   eb1b                 | jmp                 0x1d
            //   8d8de8feffff         | lea                 ecx, [ebp - 0x118]

        $sequence_5 = { eb1b 8bc6 c1f805 8b0485c0f50210 83e61f c1e606 8d443004 }
            // n = 7, score = 100
            //   eb1b                 | jmp                 0x1d
            //   8bc6                 | mov                 eax, esi
            //   c1f805               | sar                 eax, 5
            //   8b0485c0f50210       | mov                 eax, dword ptr [eax*4 + 0x1002f5c0]
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   8d443004             | lea                 eax, [eax + esi + 4]

        $sequence_6 = { 895d88 895d84 33ff e8???????? 8d4584 50 8d4588 }
            // n = 7, score = 100
            //   895d88               | mov                 dword ptr [ebp - 0x78], ebx
            //   895d84               | mov                 dword ptr [ebp - 0x7c], ebx
            //   33ff                 | xor                 edi, edi
            //   e8????????           |                     
            //   8d4584               | lea                 eax, [ebp - 0x7c]
            //   50                   | push                eax
            //   8d4588               | lea                 eax, [ebp - 0x78]

        $sequence_7 = { 33c0 8945fc 895de4 c745ec886d0210 c745f001010000 c745f41e010000 c745f80f000000 }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   895de4               | mov                 dword ptr [ebp - 0x1c], ebx
            //   c745ec886d0210       | mov                 dword ptr [ebp - 0x14], 0x10026d88
            //   c745f001010000       | mov                 dword ptr [ebp - 0x10], 0x101
            //   c745f41e010000       | mov                 dword ptr [ebp - 0xc], 0x11e
            //   c745f80f000000       | mov                 dword ptr [ebp - 8], 0xf

        $sequence_8 = { 0fb712 43 3bd9 8955fc 7d08 3bfa }
            // n = 6, score = 100
            //   0fb712               | movzx               edx, word ptr [edx]
            //   43                   | inc                 ebx
            //   3bd9                 | cmp                 ebx, ecx
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   7d08                 | jge                 0xa
            //   3bfa                 | cmp                 edi, edx

        $sequence_9 = { 5f 5b c9 c20800 33d2 385014 7509 }
            // n = 7, score = 100
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   c20800               | ret                 8
            //   33d2                 | xor                 edx, edx
            //   385014               | cmp                 byte ptr [eax + 0x14], dl
            //   7509                 | jne                 0xb

    condition:
        7 of them and filesize < 429056
}