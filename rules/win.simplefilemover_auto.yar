rule win_simplefilemover_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.simplefilemover."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.simplefilemover"
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
        $sequence_0 = { f3a5 e8???????? 81c420020000 85c0 }
            // n = 4, score = 600
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   e8????????           |                     
            //   81c420020000         | add                 esp, 0x220
            //   85c0                 | test                eax, eax

        $sequence_1 = { 7d07 33c0 e9???????? 6820020000 }
            // n = 4, score = 500
            //   7d07                 | jge                 9
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   6820020000           | push                0x220

        $sequence_2 = { 81c420020000 85c0 7407 68???????? eb05 68???????? ff15???????? }
            // n = 7, score = 300
            //   81c420020000         | add                 esp, 0x220
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   68????????           |                     
            //   eb05                 | jmp                 7
            //   68????????           |                     
            //   ff15????????         |                     

        $sequence_3 = { 56 57 c78508daffff00000000 c78520daffff00000000 c78518daffff00000000 }
            // n = 5, score = 300
            //   56                   | push                esi
            //   57                   | push                edi
            //   c78508daffff00000000     | mov    dword ptr [ebp - 0x25f8], 0
            //   c78520daffff00000000     | mov    dword ptr [ebp - 0x25e0], 0
            //   c78518daffff00000000     | mov    dword ptr [ebp - 0x25e8], 0

        $sequence_4 = { b988000000 8bf3 8bfc f3a5 }
            // n = 4, score = 300
            //   b988000000           | mov                 ecx, 0x88
            //   8bf3                 | mov                 esi, ebx
            //   8bfc                 | mov                 edi, esp
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]

        $sequence_5 = { 6a04 8d8d54daffff 51 8b9554faffff 52 ff15???????? }
            // n = 6, score = 300
            //   6a04                 | push                4
            //   8d8d54daffff         | lea                 ecx, [ebp - 0x25ac]
            //   51                   | push                ecx
            //   8b9554faffff         | mov                 edx, dword ptr [ebp - 0x5ac]
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_6 = { 6a00 6a08 8d8554daffff 50 8b8d54faffff 51 ff15???????? }
            // n = 7, score = 300
            //   6a00                 | push                0
            //   6a08                 | push                8
            //   8d8554daffff         | lea                 eax, [ebp - 0x25ac]
            //   50                   | push                eax
            //   8b8d54faffff         | mov                 ecx, dword ptr [ebp - 0x5ac]
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_7 = { 8d9558daffff 52 e8???????? 83c40c 6a04 8d8540daffff 50 }
            // n = 7, score = 300
            //   8d9558daffff         | lea                 edx, [ebp - 0x25a8]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a04                 | push                4
            //   8d8540daffff         | lea                 eax, [ebp - 0x25c0]
            //   50                   | push                eax

        $sequence_8 = { 6a00 6a00 8d8554daffff 50 8b8d04daffff }
            // n = 5, score = 300
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d8554daffff         | lea                 eax, [ebp - 0x25ac]
            //   50                   | push                eax
            //   8b8d04daffff         | mov                 ecx, dword ptr [ebp - 0x25fc]

        $sequence_9 = { 50 e8???????? 83c40c 8b8d40daffff 8d54091c 52 }
            // n = 6, score = 300
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8b8d40daffff         | mov                 ecx, dword ptr [ebp - 0x25c0]
            //   8d54091c             | lea                 edx, [ecx + ecx + 0x1c]
            //   52                   | push                edx

        $sequence_10 = { 8b44241c 56 8b74241c 57 8a8800010000 8a9001010000 }
            // n = 6, score = 200
            // 
            //   56                   | push                esi
            //   8b74241c             | mov                 esi, dword ptr [esp + 0x1c]
            //   57                   | push                edi
            //   8a8800010000         | mov                 cl, byte ptr [eax + 0x100]
            //   8a9001010000         | mov                 dl, byte ptr [eax + 0x101]

        $sequence_11 = { 51 e8???????? 8b7c2424 b940000000 f3a5 83c40c 66a5 }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8b7c2424             | mov                 edi, dword ptr [esp + 0x24]
            //   b940000000           | mov                 ecx, 0x40
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   83c40c               | add                 esp, 0xc
            //   66a5                 | movsw               word ptr es:[edi], word ptr [esi]

        $sequence_12 = { 8a1c01 885c241c 81e3ff000000 03de }
            // n = 4, score = 200
            //   8a1c01               | mov                 bl, byte ptr [ecx + eax]
            //   885c241c             | mov                 byte ptr [esp + 0x1c], bl
            //   81e3ff000000         | and                 ebx, 0xff
            //   03de                 | add                 ebx, esi

        $sequence_13 = { 884c2408 3bf7 88542424 897c2410 }
            // n = 4, score = 200
            //   884c2408             | mov                 byte ptr [esp + 8], cl
            //   3bf7                 | cmp                 esi, edi
            //   88542424             | mov                 byte ptr [esp + 0x24], dl
            //   897c2410             | mov                 dword ptr [esp + 0x10], edi

        $sequence_14 = { ff75fc ebd8 8d85a4ddffff 57 50 e8???????? 8d85a4ddffff }
            // n = 7, score = 200
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ebd8                 | jmp                 0xffffffda
            //   8d85a4ddffff         | lea                 eax, [ebp - 0x225c]
            //   57                   | push                edi
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d85a4ddffff         | lea                 eax, [ebp - 0x225c]

        $sequence_15 = { 301c2f 8b7c2418 8b5c2428 47 897c2418 0fbfff 3bfb }
            // n = 7, score = 200
            //   301c2f               | xor                 byte ptr [edi + ebp], bl
            //   8b7c2418             | mov                 edi, dword ptr [esp + 0x18]
            //   8b5c2428             | mov                 ebx, dword ptr [esp + 0x28]
            //   47                   | inc                 edi
            //   897c2418             | mov                 dword ptr [esp + 0x18], edi
            //   0fbfff               | movsx               edi, di
            //   3bfb                 | cmp                 edi, ebx

        $sequence_16 = { 8b4c2414 8d447b02 50 51 }
            // n = 4, score = 200
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   8d447b02             | lea                 eax, [ebx + edi*2 + 2]
            //   50                   | push                eax
            //   51                   | push                ecx

        $sequence_17 = { 8d85a4fdffff 50 8d85b4ddffff 50 e8???????? }
            // n = 5, score = 200
            //   8d85a4fdffff         | lea                 eax, [ebp - 0x25c]
            //   50                   | push                eax
            //   8d85b4ddffff         | lea                 eax, [ebp - 0x224c]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_18 = { 0fbf45f8 3b450c 8945f4 7c99 8a4513 8a55ff }
            // n = 6, score = 200
            //   0fbf45f8             | movsx               eax, word ptr [ebp - 8]
            //   3b450c               | cmp                 eax, dword ptr [ebp + 0xc]
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   7c99                 | jl                  0xffffff9b
            //   8a4513               | mov                 al, byte ptr [ebp + 0x13]
            //   8a55ff               | mov                 dl, byte ptr [ebp - 1]

        $sequence_19 = { 885c242c 8a5c241c 8b74242c 885c2414 }
            // n = 4, score = 200
            //   885c242c             | mov                 byte ptr [esp + 0x2c], bl
            //   8a5c241c             | mov                 bl, byte ptr [esp + 0x1c]
            //   8b74242c             | mov                 esi, dword ptr [esp + 0x2c]
            //   885c2414             | mov                 byte ptr [esp + 0x14], bl

        $sequence_20 = { 53 6a03 53 53 8d85a4fdffff 6800000080 50 }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   6a03                 | push                3
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   8d85a4fdffff         | lea                 eax, [ebp - 0x25c]
            //   6800000080           | push                0x80000000
            //   50                   | push                eax

        $sequence_21 = { 7433 8bcb 663d5c00 7503 8bfa }
            // n = 5, score = 200
            //   7433                 | je                  0x35
            //   8bcb                 | mov                 ecx, ebx
            //   663d5c00             | cmp                 ax, 0x5c
            //   7503                 | jne                 5
            //   8bfa                 | mov                 edi, edx

    condition:
        7 of them and filesize < 73728
}