rule win_hlux_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.hlux."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hlux"
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
        $sequence_0 = { 0009 1b4e01 e405 9d }
            // n = 4, score = 100
            //   0009                 | add                 byte ptr [ecx], cl
            //   1b4e01               | sbb                 ecx, dword ptr [esi + 1]
            //   e405                 | in                  al, 5
            //   9d                   | popfd               

        $sequence_1 = { 740e 21c9 750a 21c9 7506 898d24ffffff 33ff }
            // n = 7, score = 100
            //   740e                 | je                  0x10
            //   21c9                 | and                 ecx, ecx
            //   750a                 | jne                 0xc
            //   21c9                 | and                 ecx, ecx
            //   7506                 | jne                 8
            //   898d24ffffff         | mov                 dword ptr [ebp - 0xdc], ecx
            //   33ff                 | xor                 edi, edi

        $sequence_2 = { 899d84feffff b9fe09dfe3 33c0 85f6 7576 }
            // n = 5, score = 100
            //   899d84feffff         | mov                 dword ptr [ebp - 0x17c], ebx
            //   b9fe09dfe3           | mov                 ecx, 0xe3df09fe
            //   33c0                 | xor                 eax, eax
            //   85f6                 | test                esi, esi
            //   7576                 | jne                 0x78

        $sequence_3 = { 21ff 7506 89bd24ffffff 8b05???????? 8b35???????? 89b5c0feffff }
            // n = 6, score = 100
            //   21ff                 | and                 edi, edi
            //   7506                 | jne                 8
            //   89bd24ffffff         | mov                 dword ptr [ebp - 0xdc], edi
            //   8b05????????         |                     
            //   8b35????????         |                     
            //   89b5c0feffff         | mov                 dword ptr [ebp - 0x140], esi

        $sequence_4 = { 8995c8feffff 648b3518000000 8b8dc4feffff 8b1d???????? }
            // n = 4, score = 100
            //   8995c8feffff         | mov                 dword ptr [ebp - 0x138], edx
            //   648b3518000000       | mov                 esi, dword ptr fs:[0x18]
            //   8b8dc4feffff         | mov                 ecx, dword ptr [ebp - 0x13c]
            //   8b1d????????         |                     

        $sequence_5 = { 0130 8b13 8b08 85d2 }
            // n = 4, score = 100
            //   0130                 | add                 dword ptr [eax], esi
            //   8b13                 | mov                 edx, dword ptr [ebx]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   85d2                 | test                edx, edx

        $sequence_6 = { 894d80 899548ffffff 83fe75 7406 89b51cffffff 8b9d84feffff }
            // n = 6, score = 100
            //   894d80               | mov                 dword ptr [ebp - 0x80], ecx
            //   899548ffffff         | mov                 dword ptr [ebp - 0xb8], edx
            //   83fe75               | cmp                 esi, 0x75
            //   7406                 | je                  8
            //   89b51cffffff         | mov                 dword ptr [ebp - 0xe4], esi
            //   8b9d84feffff         | mov                 ebx, dword ptr [ebp - 0x17c]

        $sequence_7 = { 09c0 750b 81f8cb92129a 7503 8945fc }
            // n = 5, score = 100
            //   09c0                 | or                  eax, eax
            //   750b                 | jne                 0xd
            //   81f8cb92129a         | cmp                 eax, 0x9a1292cb
            //   7503                 | jne                 5
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_8 = { 010f 840f 0000 008365f0fe8b }
            // n = 4, score = 100
            //   010f                 | add                 dword ptr [edi], ecx
            //   840f                 | test                byte ptr [edi], cl
            //   0000                 | add                 byte ptr [eax], al
            //   008365f0fe8b         | add                 byte ptr [ebx - 0x74010f9b], al

        $sequence_9 = { 33f6 81fe230cbf1a 0f84be000000 81fe8edf8a2a }
            // n = 4, score = 100
            //   33f6                 | xor                 esi, esi
            //   81fe230cbf1a         | cmp                 esi, 0x1abf0c23
            //   0f84be000000         | je                  0xc4
            //   81fe8edf8a2a         | cmp                 esi, 0x2a8adf8e

        $sequence_10 = { 0088aa4b0023 d18a0688078a 46 018847018a46 }
            // n = 4, score = 100
            //   0088aa4b0023         | add                 byte ptr [eax + 0x23004baa], cl
            //   d18a0688078a         | ror                 dword ptr [edx - 0x75f877fa], 1
            //   46                   | inc                 esi
            //   018847018a46         | add                 dword ptr [eax + 0x468a0147], ecx

        $sequence_11 = { 0101 c9 c3 6a10 }
            // n = 4, score = 100
            //   0101                 | add                 dword ptr [ecx], eax
            //   c9                   | leave               
            //   c3                   | ret                 
            //   6a10                 | push                0x10

        $sequence_12 = { 81fb7cdcb739 7506 899d70feffff 85c0 }
            // n = 4, score = 100
            //   81fb7cdcb739         | cmp                 ebx, 0x39b7dc7c
            //   7506                 | jne                 8
            //   899d70feffff         | mov                 dword ptr [ebp - 0x190], ebx
            //   85c0                 | test                eax, eax

        $sequence_13 = { 0104bb 8d1447 89542418 e9???????? }
            // n = 4, score = 100
            //   0104bb               | add                 dword ptr [ebx + edi*4], eax
            //   8d1447               | lea                 edx, [edi + eax*2]
            //   89542418             | mov                 dword ptr [esp + 0x18], edx
            //   e9????????           |                     

        $sequence_14 = { 0104b9 33c9 83c408 85c0 }
            // n = 4, score = 100
            //   0104b9               | add                 dword ptr [ecx + edi*4], eax
            //   33c9                 | xor                 ecx, ecx
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax

        $sequence_15 = { 0000 008365f0fe8b 4d 0883c108e918 }
            // n = 4, score = 100
            //   0000                 | add                 byte ptr [eax], al
            //   008365f0fe8b         | add                 byte ptr [ebx - 0x74010f9b], al
            //   4d                   | dec                 ebp
            //   0883c108e918         | or                  byte ptr [ebx + 0x18e908c1], al

    condition:
        7 of them and filesize < 3147776
}