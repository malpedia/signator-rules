rule win_hardrain_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.hardrain."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hardrain"
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
        $sequence_0 = { 68???????? 6851520000 51 e8???????? }
            // n = 4, score = 200
            //   68????????           |                     
            //   6851520000           | push                0x5251
            //   51                   | push                ecx
            //   e8????????           |                     

        $sequence_1 = { 8bce 6a14 53 50 e8???????? }
            // n = 5, score = 200
            //   8bce                 | mov                 ecx, esi
            //   6a14                 | push                0x14
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_2 = { 55 56 85c0 7463 }
            // n = 4, score = 200
            //   55                   | push                ebp
            //   56                   | push                esi
            //   85c0                 | test                eax, eax
            //   7463                 | je                  0x65

        $sequence_3 = { 8b06 6a02 8b4804 51 }
            // n = 4, score = 200
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   6a02                 | push                2
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   51                   | push                ecx

        $sequence_4 = { ff15???????? 83f8ff 747d 8d4c2414 6a10 }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   83f8ff               | cmp                 eax, -1
            //   747d                 | je                  0x7f
            //   8d4c2414             | lea                 ecx, [esp + 0x14]
            //   6a10                 | push                0x10

        $sequence_5 = { 52 51 e8???????? 83c40c 8b842414010000 }
            // n = 5, score = 200
            //   52                   | push                edx
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8b842414010000       | mov                 eax, dword ptr [esp + 0x114]

        $sequence_6 = { f3a4 5f 750a 55 53 }
            // n = 5, score = 200
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   5f                   | pop                 edi
            //   750a                 | jne                 0xc
            //   55                   | push                ebp
            //   53                   | push                ebx

        $sequence_7 = { 83c40c eb14 3d59340000 750d 8b4c2404 51 }
            // n = 6, score = 200
            //   83c40c               | add                 esp, 0xc
            //   eb14                 | jmp                 0x16
            //   3d59340000           | cmp                 eax, 0x3459
            //   750d                 | jne                 0xf
            //   8b4c2404             | mov                 ecx, dword ptr [esp + 4]
            //   51                   | push                ecx

        $sequence_8 = { 56 8b7104 8bc2 c1e80b 83e001 33f0 }
            // n = 6, score = 200
            //   56                   | push                esi
            //   8b7104               | mov                 esi, dword ptr [ecx + 4]
            //   8bc2                 | mov                 eax, edx
            //   c1e80b               | shr                 eax, 0xb
            //   83e001               | and                 eax, 1
            //   33f0                 | xor                 esi, eax

        $sequence_9 = { ff15???????? 663dc800 720a 5f 5e 5d }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   663dc800             | cmp                 ax, 0xc8
            //   720a                 | jb                  0xc
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp

    condition:
        7 of them and filesize < 368640
}