rule win_cueisfry_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.cueisfry."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cueisfry"
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
        $sequence_0 = { f3ab 66ab aa 8d84249c000000 68???????? 50 }
            // n = 6, score = 100
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8d84249c000000       | lea                 eax, [esp + 0x9c]
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_1 = { e8???????? 85c0 0f84ee000000 b91f000000 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f84ee000000         | je                  0xf4
            //   b91f000000           | mov                 ecx, 0x1f

        $sequence_2 = { 52 e8???????? 83c40c 8d4c2408 c78424b8070000ffffffff e8???????? 8b8c24b0070000 }
            // n = 7, score = 100
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d4c2408             | lea                 ecx, [esp + 8]
            //   c78424b8070000ffffffff     | mov    dword ptr [esp + 0x7b8], 0xffffffff
            //   e8????????           |                     
            //   8b8c24b0070000       | mov                 ecx, dword ptr [esp + 0x7b0]

        $sequence_3 = { 83ffff 7541 b920000000 33c0 8d7c241c }
            // n = 5, score = 100
            //   83ffff               | cmp                 edi, -1
            //   7541                 | jne                 0x43
            //   b920000000           | mov                 ecx, 0x20
            //   33c0                 | xor                 eax, eax
            //   8d7c241c             | lea                 edi, [esp + 0x1c]

        $sequence_4 = { 51 6a00 68???????? 52 c644241c00 c744242020000000 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   68????????           |                     
            //   52                   | push                edx
            //   c644241c00           | mov                 byte ptr [esp + 0x1c], 0
            //   c744242020000000     | mov                 dword ptr [esp + 0x20], 0x20

        $sequence_5 = { e8???????? b940000000 33c0 8dbc24a9000000 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   b940000000           | mov                 ecx, 0x40
            //   33c0                 | xor                 eax, eax
            //   8dbc24a9000000       | lea                 edi, [esp + 0xa9]

        $sequence_6 = { 7541 397dec 750a 6803400080 e8???????? 8b4dec }
            // n = 6, score = 100
            //   7541                 | jne                 0x43
            //   397dec               | cmp                 dword ptr [ebp - 0x14], edi
            //   750a                 | jne                 0xc
            //   6803400080           | push                0x80004003
            //   e8????????           |                     
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]

        $sequence_7 = { 57 ff511c 8bd8 85db }
            // n = 4, score = 100
            //   57                   | push                edi
            //   ff511c               | call                dword ptr [ecx + 0x1c]
            //   8bd8                 | mov                 ebx, eax
            //   85db                 | test                ebx, ebx

        $sequence_8 = { e8???????? 33c0 8b8c24ac010000 5f 5e }
            // n = 5, score = 100
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   8b8c24ac010000       | mov                 ecx, dword ptr [esp + 0x1ac]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_9 = { 50 ffd5 8b4604 85c0 7409 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   ffd5                 | call                ebp
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   85c0                 | test                eax, eax
            //   7409                 | je                  0xb

    condition:
        7 of them and filesize < 81920
}