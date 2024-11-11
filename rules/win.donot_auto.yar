rule win_donot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.donot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.donot"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
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
        $sequence_0 = { c7461407000000 668906 8b95ccfcffff 83fa08 7235 }
            // n = 5, score = 100
            //   c7461407000000       | mov                 dword ptr [esi + 0x14], 7
            //   668906               | mov                 word ptr [esi], ax
            //   8b95ccfcffff         | mov                 edx, dword ptr [ebp - 0x334]
            //   83fa08               | cmp                 edx, 8
            //   7235                 | jb                  0x37

        $sequence_1 = { 52 50 8b08 ff511c 6a0c e8???????? }
            // n = 6, score = 100
            //   52                   | push                edx
            //   50                   | push                eax
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff511c               | call                dword ptr [ecx + 0x1c]
            //   6a0c                 | push                0xc
            //   e8????????           |                     

        $sequence_2 = { 83fa08 7231 8b8dc8fdffff 8d145502000000 8bc1 81fa00100000 7210 }
            // n = 7, score = 100
            //   83fa08               | cmp                 edx, 8
            //   7231                 | jb                  0x33
            //   8b8dc8fdffff         | mov                 ecx, dword ptr [ebp - 0x238]
            //   8d145502000000       | lea                 edx, [edx*2 + 2]
            //   8bc1                 | mov                 eax, ecx
            //   81fa00100000         | cmp                 edx, 0x1000
            //   7210                 | jb                  0x12

        $sequence_3 = { 8b06 8b4004 c70406???????? 8b06 8b5004 8d4290 }
            // n = 6, score = 100
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   c70406????????       |                     
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8b5004               | mov                 edx, dword ptr [eax + 4]
            //   8d4290               | lea                 eax, [edx - 0x70]

        $sequence_4 = { 8d8d68fdffff 6a20 ffb5c0fdffff 33c0 c78568fdffff00000000 c78578fdffff00000000 }
            // n = 6, score = 100
            //   8d8d68fdffff         | lea                 ecx, [ebp - 0x298]
            //   6a20                 | push                0x20
            //   ffb5c0fdffff         | push                dword ptr [ebp - 0x240]
            //   33c0                 | xor                 eax, eax
            //   c78568fdffff00000000     | mov    dword ptr [ebp - 0x298], 0
            //   c78578fdffff00000000     | mov    dword ptr [ebp - 0x288], 0

        $sequence_5 = { 8b49fc 83c223 2bc1 83c0fc 83f81f 0f87b4150000 52 }
            // n = 7, score = 100
            //   8b49fc               | mov                 ecx, dword ptr [ecx - 4]
            //   83c223               | add                 edx, 0x23
            //   2bc1                 | sub                 eax, ecx
            //   83c0fc               | add                 eax, -4
            //   83f81f               | cmp                 eax, 0x1f
            //   0f87b4150000         | ja                  0x15ba
            //   52                   | push                edx

        $sequence_6 = { 83f8ff 7507 33f6 e9???????? 6a00 50 }
            // n = 6, score = 100
            //   83f8ff               | cmp                 eax, -1
            //   7507                 | jne                 9
            //   33f6                 | xor                 esi, esi
            //   e9????????           |                     
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_7 = { 50 e8???????? 8bb5e4e7ffff 8bc6 8b95e0e7ffff 2bc2 83f801 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bb5e4e7ffff         | mov                 esi, dword ptr [ebp - 0x181c]
            //   8bc6                 | mov                 eax, esi
            //   8b95e0e7ffff         | mov                 edx, dword ptr [ebp - 0x1820]
            //   2bc2                 | sub                 eax, edx
            //   83f801               | cmp                 eax, 1

        $sequence_8 = { e9???????? 833d????????00 0f858cc60000 8d0d50990310 ba1d000000 e8???????? 5a }
            // n = 7, score = 100
            //   e9????????           |                     
            //   833d????????00       |                     
            //   0f858cc60000         | jne                 0xc692
            //   8d0d50990310         | lea                 ecx, [0x10039950]
            //   ba1d000000           | mov                 edx, 0x1d
            //   e8????????           |                     
            //   5a                   | pop                 edx

        $sequence_9 = { 50 8d45f4 64a300000000 8b01 8d7968 8b4004 c744389878210410 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   8d7968               | lea                 edi, [ecx + 0x68]
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   c744389878210410     | mov                 dword ptr [eax + edi - 0x68], 0x10042178

    condition:
        7 of them and filesize < 626688
}