rule win_cobra_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.cobra."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobra"
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
        $sequence_0 = { 7511 e8???????? 85c0 7508 ff15???????? }
            // n = 5, score = 3100
            //   7511                 | cmp                 eax, -1
            //   e8????????           |                     
            //   85c0                 | je                  9
            //   7508                 | xor                 eax, eax
            //   ff15????????         |                     

        $sequence_1 = { 5e 5b c3 85ff 7418 }
            // n = 5, score = 2800
            //   5e                   | push                eax
            //   5b                   | mov                 dword ptr [esp + 0xa0], eax
            //   c3                   | push                0x208
            //   85ff                 | lea                 eax, [esp + 0x2b0]
            //   7418                 | push                ebx

        $sequence_2 = { 83fb01 7405 83fb02 7537 }
            // n = 4, score = 2800
            //   83fb01               | mov                 dword ptr [esp + 0xa0], eax
            //   7405                 | push                0x208
            //   83fb02               | lea                 eax, [esp + 0x2b0]
            //   7537                 | push                ebx

        $sequence_3 = { 85c0 750e 33ff 8bc7 }
            // n = 4, score = 2800
            //   85c0                 | test                eax, eax
            //   750e                 | jne                 0x81
            //   33ff                 | test                eax, eax
            //   8bc7                 | jle                 0x96

        $sequence_4 = { 7514 391d???????? 754d 33c0 }
            // n = 4, score = 2800
            //   7514                 | cmp                 ebx, 1
            //   391d????????         |                     
            //   754d                 | je                  0xb
            //   33c0                 | cmp                 ebx, 2

        $sequence_5 = { 5b c3 85db 7405 83fb03 753b }
            // n = 6, score = 2800
            //   5b                   | cmp                 ebx, 2
            //   c3                   | jne                 0x42
            //   85db                 | pop                 esi
            //   7405                 | pop                 ebx
            //   83fb03               | ret                 
            //   753b                 | cmp                 ebx, 1

        $sequence_6 = { 83f801 75f1 b900010000 e8???????? }
            // n = 4, score = 2800
            //   83f801               | jne                 0x42
            //   75f1                 | mov                 eax, dword ptr [esp + 0x38]
            //   b900010000           | test                eax, eax
            //   e8????????           |                     

        $sequence_7 = { 757f 8b05???????? 85c0 0f8e8c000000 }
            // n = 4, score = 2800
            //   757f                 | push                0x208
            //   8b05????????         |                     
            //   85c0                 | lea                 eax, [esp + 0x2b0]
            //   0f8e8c000000         | push                ebx

        $sequence_8 = { 751c 8bcf ff15???????? 8d8fe8030000 }
            // n = 4, score = 2800
            //   751c                 | pop                 esi
            //   8bcf                 | pop                 ebx
            //   ff15????????         |                     
            //   8d8fe8030000         | ret                 

        $sequence_9 = { 85c0 750e 3905???????? 7e2c }
            // n = 4, score = 2700
            //   85c0                 | lea                 eax, [ebp - 0x120]
            //   750e                 | mov                 ecx, dword ptr [ebp + 8]
            //   3905????????         |                     
            //   7e2c                 | mov                 eax, dword ptr [ecx + 0x20]

        $sequence_10 = { c20c00 ff25???????? 53 56 57 8bd9 33f6 }
            // n = 7, score = 2700
            //   c20c00               | test                eax, eax
            //   ff25????????         |                     
            //   53                   | jne                 0x12
            //   56                   | jle                 0x2e
            //   57                   | cmp                 eax, 1
            //   8bd9                 | test                eax, eax
            //   33f6                 | jne                 0x12

        $sequence_11 = { 753c b980000000 e8???????? 85c0 a3???????? }
            // n = 5, score = 2700
            //   753c                 | mov                 ecx, dword ptr [ebp + 8]
            //   b980000000           | mov                 dword ptr [ecx], edx
            //   e8????????           |                     
            //   85c0                 | xor                 eax, eax
            //   a3????????           |                     

        $sequence_12 = { 85c0 a3???????? 7504 33c0 eb68 832000 a1???????? }
            // n = 7, score = 2700
            //   85c0                 | test                eax, eax
            //   a3????????           |                     
            //   7504                 | mov                 eax, dword ptr [esp + 8]
            //   33c0                 | test                eax, eax
            //   eb68                 | jne                 0x10
            //   832000               | jle                 0x30
            //   a1????????           |                     

        $sequence_13 = { 33d2 b9e8030000 f7f1 83f805 }
            // n = 4, score = 2500
            //   33d2                 | mov                 ebx, ecx
            //   b9e8030000           | xor                 esi, esi
            //   f7f1                 | push                ebx
            //   83f805               | push                ebx

        $sequence_14 = { 83f8ff 7407 33c0 e9???????? ff15???????? e9???????? }
            // n = 6, score = 2100
            //   83f8ff               | jmp                 0x6c
            //   7407                 | mov                 eax, dword ptr [esp + 8]
            //   33c0                 | test                eax, eax
            //   e9????????           |                     
            //   ff15????????         |                     
            //   e9????????           |                     

        $sequence_15 = { ff15???????? 385dff 75d2 eb0c 53 }
            // n = 5, score = 2100
            //   ff15????????         |                     
            //   385dff               | test                eax, eax
            //   75d2                 | jne                 6
            //   eb0c                 | xor                 eax, eax
            //   53                   | jmp                 0x6e

        $sequence_16 = { eb0e 8d4608 50 e8???????? 8b4508 8930 59 }
            // n = 7, score = 2100
            //   eb0e                 | jne                 0xd
            //   8d4608               | mov                 ecx, dword ptr [ecx]
            //   50                   | jne                 0x3e
            //   e8????????           |                     
            //   8b4508               | mov                 ecx, 0x80
            //   8930                 | test                eax, eax
            //   59                   | cmp                 dword ptr [eax + ecx], 0x4550

        $sequence_17 = { e8???????? 33db 3bc3 741a }
            // n = 4, score = 1400
            //   e8????????           |                     
            //   33db                 | xor                 ebx, ebx
            //   3bc3                 | cmp                 eax, ebx
            //   741a                 | je                  0x1c

        $sequence_18 = { eb6d e8???????? 85c0 7564 }
            // n = 4, score = 1400
            //   eb6d                 | jmp                 0x6f
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7564                 | jne                 0x66

        $sequence_19 = { 85c0 7f07 e8???????? eb26 }
            // n = 4, score = 1400
            //   85c0                 | test                eax, eax
            //   7f07                 | jg                  9
            //   e8????????           |                     
            //   eb26                 | jmp                 0x28

        $sequence_20 = { e8???????? 48832700 ba02000000 488bce e8???????? 498bce e8???????? }
            // n = 7, score = 1100
            //   e8????????           |                     
            //   48832700             | jmp                 0x10
            //   ba02000000           | dec                 eax
            //   488bce               | add                 ecx, 8
            //   e8????????           |                     
            //   498bce               | mov                 eax, 0x21590001
            //   e8????????           |                     

        $sequence_21 = { b801005921 488b5c2430 488b742438 4883c420 }
            // n = 4, score = 1100
            //   b801005921           | dec                 eax
            //   488b5c2430           | mov                 ebx, dword ptr [esp + 0x40]
            //   488b742438           | dec                 eax
            //   4883c420             | and                 dword ptr [edi], 0

        $sequence_22 = { eb0e 4883c108 e8???????? b801005921 488b5c2440 }
            // n = 5, score = 1100
            //   eb0e                 | dec                 esp
            //   4883c108             | mov                 edx, dword ptr [eax + 0x5c]
            //   e8????????           |                     
            //   b801005921           | dec                 ebp
            //   488b5c2440           | test                edx, edx

        $sequence_23 = { 750b 4883c108 e8???????? eb0c bb06005921 eb05 bb65005921 }
            // n = 7, score = 1100
            //   750b                 | jne                 0xd
            //   4883c108             | dec                 eax
            //   e8????????           |                     
            //   eb0c                 | add                 ecx, 8
            //   bb06005921           | jmp                 0xe
            //   eb05                 | mov                 ebx, 0x21590006
            //   bb65005921           | jmp                 7

        $sequence_24 = { 83385c 7e4b 4c8b505c 4d85d2 }
            // n = 4, score = 1100
            //   83385c               | cmp                 eax, ebx
            //   7e4b                 | je                  0x1c
            //   4c8b505c             | cmp                 dword ptr [eax], 0x5c
            //   4d85d2               | jle                 0x4d

        $sequence_25 = { 50 6a00 6aff e8???????? 85c0 7405 }
            // n = 6, score = 1000
            //   50                   | add                 esp, 0x20
            //   6a00                 | mov                 eax, 0x21590001
            //   6aff                 | dec                 eax
            //   e8????????           |                     
            //   85c0                 | mov                 ebx, dword ptr [esp + 0x30]
            //   7405                 | dec                 eax

        $sequence_26 = { 895c2428 895c2434 895c2430 895c2424 895c2420 885c241f e8???????? }
            // n = 7, score = 900
            //   895c2428             | xor                 eax, eax
            //   895c2434             | jmp                 0x6e
            //   895c2430             | and                 dword ptr [eax], 0
            //   895c2424             | test                eax, eax
            //   895c2420             | jne                 8
            //   885c241f             | xor                 eax, eax
            //   e8????????           |                     

        $sequence_27 = { 89842490000000 89842494000000 89842498000000 8984249c000000 898424a0000000 e8???????? 6808020000 }
            // n = 7, score = 900
            //   89842490000000       | mov                 dword ptr [ebp - 4], esi
            //   89842494000000       | push                0x11c
            //   89842498000000       | lea                 ecx, [ebp - 0x120]
            //   8984249c000000       | mov                 dword ptr [ebp - 4], esi
            //   898424a0000000       | push                0x11c
            //   e8????????           |                     
            //   6808020000           | lea                 ecx, [ebp - 0x120]

        $sequence_28 = { 83781400 750a b865005921 e9???????? }
            // n = 4, score = 900
            //   83781400             | push                0
            //   750a                 | push                -1
            //   b865005921           | test                eax, eax
            //   e9????????           |                     

        $sequence_29 = { 8975fc e8???????? 681c010000 8d8de0feffff }
            // n = 4, score = 900
            //   8975fc               | mov                 dword ptr [esp + 0x20], ebx
            //   e8????????           |                     
            //   681c010000           | mov                 dword ptr [esp + 0x34], ebx
            //   8d8de0feffff         | mov                 dword ptr [esp + 0x30], ebx

        $sequence_30 = { 898424a0000000 e8???????? 6808020000 8d8424b0020000 53 50 }
            // n = 6, score = 900
            //   898424a0000000       | mov                 dword ptr [esp + 0xa0], eax
            //   e8????????           |                     
            //   6808020000           | push                0x208
            //   8d8424b0020000       | lea                 eax, [esp + 0x2b0]
            //   53                   | push                ebx
            //   50                   | mov                 dword ptr [esp + 0x9c], eax

        $sequence_31 = { 7507 32c0 e9???????? c745b818000000 }
            // n = 4, score = 800
            //   7507                 | push                0
            //   32c0                 | push                -1
            //   e9????????           |                     
            //   c745b818000000       | test                eax, eax

        $sequence_32 = { 668cc8 c3 53 50 }
            // n = 4, score = 200
            //   668cc8               | jne                 6
            //   c3                   | xor                 eax, eax
            //   53                   | jmp                 9
            //   50                   | mov                 eax, 0x21590065

        $sequence_33 = { 85c0 740a b8050000c0 e9???????? }
            // n = 4, score = 200
            //   85c0                 | xor                 eax, eax
            //   740a                 | jne                 9
            //   b8050000c0           | xor                 al, al
            //   e9????????           |                     

        $sequence_34 = { 8b4d08 8b15???????? 8911 33c0 e9???????? }
            // n = 5, score = 100
            //   8b4d08               | push                ebx
            //   8b15????????         |                     
            //   8911                 | ret                 
            //   33c0                 | mov                 ax, cs
            //   e9????????           |                     

        $sequence_35 = { 8b4d08 8b148dc8fb0400 035510 52 e8???????? b001 }
            // n = 6, score = 100
            //   8b4d08               | je                  0xe
            //   8b148dc8fb0400       | mov                 eax, 0xc0000005
            //   035510               | test                eax, eax
            //   52                   | je                  0xe
            //   e8????????           |                     
            //   b001                 | mov                 eax, 0xc0000005

    condition:
        7 of them and filesize < 1368064
}