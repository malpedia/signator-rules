rule win_cohhoc_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.cohhoc."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cohhoc"
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
        $sequence_0 = { 8b8424dc030000 56 83c314 8b4808 51 }
            // n = 5, score = 300
            //   8b8424dc030000       | mov                 eax, dword ptr [esp + 0x3dc]
            //   56                   | push                esi
            //   83c314               | add                 ebx, 0x14
            //   8b4808               | mov                 ecx, dword ptr [eax + 8]
            //   51                   | push                ecx

        $sequence_1 = { 41 88442424 894c2430 8b4c2424 57 51 8b4c2428 }
            // n = 7, score = 300
            //   41                   | inc                 ecx
            //   88442424             | mov                 byte ptr [esp + 0x24], al
            //   894c2430             | mov                 dword ptr [esp + 0x30], ecx
            //   8b4c2424             | mov                 ecx, dword ptr [esp + 0x24]
            //   57                   | push                edi
            //   51                   | push                ecx
            //   8b4c2428             | mov                 ecx, dword ptr [esp + 0x28]

        $sequence_2 = { ff15???????? 85c0 7535 8b15???????? }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7535                 | jne                 0x37
            //   8b15????????         |                     

        $sequence_3 = { 68???????? 6a00 6a00 66c7030000 ffd6 }
            // n = 5, score = 300
            //   68????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   66c7030000           | mov                 word ptr [ebx], 0
            //   ffd6                 | call                esi

        $sequence_4 = { 89450c eb44 b9???????? 85c9 7505 89450c eb36 }
            // n = 7, score = 300
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   eb44                 | jmp                 0x46
            //   b9????????           |                     
            //   85c9                 | test                ecx, ecx
            //   7505                 | jne                 7
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   eb36                 | jmp                 0x38

        $sequence_5 = { 8808 668b5604 66895002 8b5604 8b0e 42 41 }
            // n = 7, score = 300
            //   8808                 | mov                 byte ptr [eax], cl
            //   668b5604             | mov                 dx, word ptr [esi + 4]
            //   66895002             | mov                 word ptr [eax + 2], dx
            //   8b5604               | mov                 edx, dword ptr [esi + 4]
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   42                   | inc                 edx
            //   41                   | inc                 ecx

        $sequence_6 = { 50 64892500000000 83ec30 56 33f6 56 8d4c240c }
            // n = 7, score = 300
            //   50                   | push                eax
            //   64892500000000       | mov                 dword ptr fs:[0], esp
            //   83ec30               | sub                 esp, 0x30
            //   56                   | push                esi
            //   33f6                 | xor                 esi, esi
            //   56                   | push                esi
            //   8d4c240c             | lea                 ecx, [esp + 0xc]

        $sequence_7 = { 0f84fb000000 bf???????? 8db424b4010000 8a0e 8a17 8ac1 3aca }
            // n = 7, score = 300
            //   0f84fb000000         | je                  0x101
            //   bf????????           |                     
            //   8db424b4010000       | lea                 esi, [esp + 0x1b4]
            //   8a0e                 | mov                 cl, byte ptr [esi]
            //   8a17                 | mov                 dl, byte ptr [edi]
            //   8ac1                 | mov                 al, cl
            //   3aca                 | cmp                 cl, dl

        $sequence_8 = { f3ab 8bac24243c0000 8b9c242c3c0000 66ab aa b9000f0000 33c0 }
            // n = 7, score = 300
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8bac24243c0000       | mov                 ebp, dword ptr [esp + 0x3c24]
            //   8b9c242c3c0000       | mov                 ebx, dword ptr [esp + 0x3c2c]
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al
            //   b9000f0000           | mov                 ecx, 0xf00
            //   33c0                 | xor                 eax, eax

        $sequence_9 = { 6a00 50 53 f3a5 ff15???????? b90a000000 8bf5 }
            // n = 7, score = 300
            //   6a00                 | push                0
            //   50                   | push                eax
            //   53                   | push                ebx
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   ff15????????         |                     
            //   b90a000000           | mov                 ecx, 0xa
            //   8bf5                 | mov                 esi, ebp

    condition:
        7 of them and filesize < 253952
}