rule win_grease_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.grease."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.grease"
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
        $sequence_0 = { 52 50 683f000f00 50 50 50 }
            // n = 6, score = 400
            //   52                   | push                edx
            //   50                   | push                eax
            //   683f000f00           | push                0xf003f
            //   50                   | push                eax
            //   50                   | push                eax
            //   50                   | push                eax

        $sequence_1 = { 48897c2430 4533c0 c74424283f000f00 897c2420 ff15???????? 85c0 }
            // n = 6, score = 300
            //   48897c2430           | inc                 ecx
            //   4533c0               | mov                 ecx, 4
            //   c74424283f000f00     | inc                 ebp
            //   897c2420             | xor                 eax, eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_2 = { 4533c9 48897c2440 4889442438 48897c2430 }
            // n = 4, score = 300
            //   4533c9               | inc                 ebp
            //   48897c2440           | xor                 ecx, ecx
            //   4889442438           | dec                 eax
            //   48897c2430           | mov                 dword ptr [esp + 0x40], edi

        $sequence_3 = { 48897c2440 488d442450 4889442438 48897c2430 }
            // n = 4, score = 300
            //   48897c2440           | mov                 edx, ebx
            //   488d442450           | mov                 dword ptr [esp + 0x28], 4
            //   4889442438           | dec                 eax
            //   48897c2430           | mov                 dword ptr [esp + 0x20], eax

        $sequence_4 = { 488b4c2460 ff15???????? b801000000 488b8c2480020000 4833cc }
            // n = 5, score = 300
            //   488b4c2460           | test                eax, eax
            //   ff15????????         |                     
            //   b801000000           | jne                 0xed
            //   488b8c2480020000     | dec                 eax
            //   4833cc               | mov                 edx, ebx

        $sequence_5 = { ff15???????? 85c0 0f85e7000000 488b4c2460 488d442458 }
            // n = 5, score = 300
            //   ff15????????         |                     
            //   85c0                 | dec                 eax
            //   0f85e7000000         | mov                 ecx, dword ptr [esp + 0x50]
            //   488b4c2460           | dec                 eax
            //   488d442458           | lea                 eax, [esp + 0x58]

        $sequence_6 = { 48895c2440 48895c2458 895c2460 48895c2468 }
            // n = 4, score = 300
            //   48895c2440           | mov                 dword ptr [esp + 0x28], 4
            //   48895c2458           | dec                 eax
            //   895c2460             | mov                 dword ptr [esp + 0x20], eax
            //   48895c2468           | dec                 eax

        $sequence_7 = { 85c0 7534 488b4c2450 488d442458 41b904000000 4533c0 }
            // n = 6, score = 300
            //   85c0                 | dec                 eax
            //   7534                 | mov                 dword ptr [esp + 0x38], eax
            //   488b4c2450           | dec                 eax
            //   488d442458           | mov                 dword ptr [esp + 0x30], edi
            //   41b904000000         | test                eax, eax
            //   4533c0               | jne                 0x36

        $sequence_8 = { 488d442458 41b904000000 4533c0 488bd3 c744242804000000 4889442420 ff15???????? }
            // n = 7, score = 300
            //   488d442458           | lea                 eax, [esp + 0x58]
            //   41b904000000         | dec                 eax
            //   4533c0               | mov                 dword ptr [esp + 0x30], edi
            //   488bd3               | inc                 ebp
            //   c744242804000000     | xor                 eax, eax
            //   4889442420           | mov                 dword ptr [esp + 0x28], 0xf003f
            //   ff15????????         |                     

        $sequence_9 = { 8b3d???????? 7502 ffd7 8d842430030000 50 8d8c2438050000 }
            // n = 6, score = 200
            //   8b3d????????         |                     
            //   7502                 | mov                 ecx, dword ptr [esp + 0x50]
            //   ffd7                 | dec                 eax
            //   8d842430030000       | lea                 eax, [esp + 0x58]
            //   50                   | inc                 ecx
            //   8d8c2438050000       | mov                 ecx, 4

        $sequence_10 = { e9???????? c644341472 e9???????? c644341469 e9???????? c644341462 e9???????? }
            // n = 7, score = 200
            //   e9????????           |                     
            //   c644341472           | mov                 byte ptr [esp + esi + 0x14], 0x72
            //   e9????????           |                     
            //   c644341469           | mov                 byte ptr [esp + esi + 0x14], 0x69
            //   e9????????           |                     
            //   c644341462           | mov                 byte ptr [esp + esi + 0x14], 0x62
            //   e9????????           |                     

        $sequence_11 = { c68434380b00002b e9???????? c68434380b00003e e9???????? }
            // n = 4, score = 200
            //   c68434380b00002b     | mov                 byte ptr [esp + esi + 0xb38], 0x2b
            //   e9????????           |                     
            //   c68434380b00003e     | mov                 byte ptr [esp + esi + 0xb38], 0x3e
            //   e9????????           |                     

        $sequence_12 = { c684342c08000068 e9???????? c684342c08000078 e9???????? c684342c08000063 e9???????? }
            // n = 6, score = 200
            //   c684342c08000068     | mov                 byte ptr [esp + esi + 0x82c], 0x68
            //   e9????????           |                     
            //   c684342c08000078     | mov                 byte ptr [esp + esi + 0x82c], 0x78
            //   e9????????           |                     
            //   c684342c08000063     | mov                 byte ptr [esp + esi + 0x82c], 0x63
            //   e9????????           |                     

        $sequence_13 = { c6440c0874 e9???????? c6440c0867 e9???????? c6440c0861 e9???????? }
            // n = 6, score = 200
            //   c6440c0874           | mov                 byte ptr [esp + ecx + 8], 0x74
            //   e9????????           |                     
            //   c6440c0867           | mov                 byte ptr [esp + ecx + 8], 0x67
            //   e9????????           |                     
            //   c6440c0861           | mov                 byte ptr [esp + ecx + 8], 0x61
            //   e9????????           |                     

        $sequence_14 = { 50 8b44242c 68???????? 50 ffd6 85c0 8b35???????? }
            // n = 7, score = 200
            //   50                   | dec                 eax
            //   8b44242c             | mov                 edx, ebx
            //   68????????           |                     
            //   50                   | mov                 dword ptr [esp + 0x28], 4
            //   ffd6                 | jne                 0x36
            //   85c0                 | dec                 eax
            //   8b35????????         |                     

        $sequence_15 = { 50 e8???????? 83c428 85c0 7409 }
            // n = 5, score = 200
            //   50                   | xor                 eax, eax
            //   e8????????           |                     
            //   83c428               | mov                 dword ptr [esp + 0x28], 0xf003f
            //   85c0                 | mov                 dword ptr [esp + 0x20], edi
            //   7409                 | dec                 eax

        $sequence_16 = { 0f85bc000000 8b4c240c 8b35???????? 50 }
            // n = 4, score = 200
            //   0f85bc000000         | mov                 ecx, 4
            //   8b4c240c             | inc                 ebp
            //   8b35????????         |                     
            //   50                   | xor                 eax, eax

        $sequence_17 = { ffd6 85c0 7533 50 8d542410 52 }
            // n = 6, score = 200
            //   ffd6                 | inc                 ebp
            //   85c0                 | xor                 eax, eax
            //   7533                 | inc                 ecx
            //   50                   | mov                 ecx, 4
            //   8d542410             | inc                 ebp
            //   52                   | xor                 eax, eax

        $sequence_18 = { 6a04 50 53 52 ff15???????? 8b44240c 50 }
            // n = 7, score = 200
            //   6a04                 | dec                 eax
            //   50                   | mov                 edx, ebx
            //   53                   | mov                 dword ptr [esp + 0x28], 4
            //   52                   | dec                 eax
            //   ff15????????         |                     
            //   8b44240c             | mov                 dword ptr [esp + 0x20], eax
            //   50                   | dec                 eax

        $sequence_19 = { b901000000 88843424060000 33c0 8a843424060000 }
            // n = 4, score = 200
            //   b901000000           | mov                 ecx, 1
            //   88843424060000       | mov                 byte ptr [esp + esi + 0x624], al
            //   33c0                 | xor                 eax, eax
            //   8a843424060000       | mov                 al, byte ptr [esp + esi + 0x624]

        $sequence_20 = { 8d442452 6a00 50 66a5 e8???????? }
            // n = 5, score = 200
            //   8d442452             | mov                 ecx, dword ptr [esp + 0x50]
            //   6a00                 | dec                 eax
            //   50                   | lea                 eax, [esp + 0x58]
            //   66a5                 | inc                 ecx
            //   e8????????           |                     

        $sequence_21 = { c68434180300002e eb08 c68434180300002c 85c9 7408 80843418030000e0 46 }
            // n = 7, score = 200
            //   c68434180300002e     | mov                 byte ptr [esp + esi + 0x318], 0x2e
            //   eb08                 | jmp                 0xa
            //   c68434180300002c     | mov                 byte ptr [esp + esi + 0x318], 0x2c
            //   85c9                 | test                ecx, ecx
            //   7408                 | je                  0xa
            //   80843418030000e0     | add                 byte ptr [esp + esi + 0x318], 0xe0
            //   46                   | inc                 esi

        $sequence_22 = { eb1c c68434280700003f eb12 c68434280700002e eb08 }
            // n = 5, score = 200
            //   eb1c                 | jmp                 0x1e
            //   c68434280700003f     | mov                 byte ptr [esp + esi + 0x728], 0x3f
            //   eb12                 | jmp                 0x14
            //   c68434280700002e     | mov                 byte ptr [esp + esi + 0x728], 0x2e
            //   eb08                 | jmp                 0xa

    condition:
        7 of them and filesize < 278528
}