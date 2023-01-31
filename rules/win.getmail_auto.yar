rule win_getmail_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.getmail."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.getmail"
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
        $sequence_0 = { 3d0b010480 7516 8b06 6a00 68e8030000 6a00 }
            // n = 6, score = 100
            //   3d0b010480           | cmp                 eax, 0x8004010b
            //   7516                 | jne                 0x18
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   6a00                 | push                0
            //   68e8030000           | push                0x3e8
            //   6a00                 | push                0

        $sequence_1 = { 50 8b10 ff5208 8b4c2418 }
            // n = 4, score = 100
            //   50                   | push                eax
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   ff5208               | call                dword ptr [edx + 8]
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]

        $sequence_2 = { 4f c1e902 f3a5 a1???????? 8bcb 83e103 85c0 }
            // n = 7, score = 100
            //   4f                   | dec                 edi
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   a1????????           |                     
            //   8bcb                 | mov                 ecx, ebx
            //   83e103               | and                 ecx, 3
            //   85c0                 | test                eax, eax

        $sequence_3 = { 8b4e04 51 56 8bcf e8???????? 894604 }
            // n = 6, score = 100
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   51                   | push                ecx
            //   56                   | push                esi
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   894604               | mov                 dword ptr [esi + 4], eax

        $sequence_4 = { 89642474 52 68???????? e8???????? 8b442424 55 50 }
            // n = 7, score = 100
            //   89642474             | mov                 dword ptr [esp + 0x74], esp
            //   52                   | push                edx
            //   68????????           |                     
            //   e8????????           |                     
            //   8b442424             | mov                 eax, dword ptr [esp + 0x24]
            //   55                   | push                ebp
            //   50                   | push                eax

        $sequence_5 = { 895c244c 895c2450 8b84243c020000 8d54247c 52 53 8b08 }
            // n = 7, score = 100
            //   895c244c             | mov                 dword ptr [esp + 0x4c], ebx
            //   895c2450             | mov                 dword ptr [esp + 0x50], ebx
            //   8b84243c020000       | mov                 eax, dword ptr [esp + 0x23c]
            //   8d54247c             | lea                 edx, [esp + 0x7c]
            //   52                   | push                edx
            //   53                   | push                ebx
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_6 = { 6a00 8b700c 8b4008 56 50 8b442474 50 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   8b700c               | mov                 esi, dword ptr [eax + 0xc]
            //   8b4008               | mov                 eax, dword ptr [eax + 8]
            //   56                   | push                esi
            //   50                   | push                eax
            //   8b442474             | mov                 eax, dword ptr [esp + 0x74]
            //   50                   | push                eax

        $sequence_7 = { ff5214 3bc5 740b 3d80030400 0f85e7010000 8b442410 bb0a000000 }
            // n = 7, score = 100
            //   ff5214               | call                dword ptr [edx + 0x14]
            //   3bc5                 | cmp                 eax, ebp
            //   740b                 | je                  0xd
            //   3d80030400           | cmp                 eax, 0x40380
            //   0f85e7010000         | jne                 0x1ed
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   bb0a000000           | mov                 ebx, 0xa

        $sequence_8 = { 49 51 e8???????? 83c404 8b4c245c 897c2448 897c244c }
            // n = 7, score = 100
            //   49                   | dec                 ecx
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b4c245c             | mov                 ecx, dword ptr [esp + 0x5c]
            //   897c2448             | mov                 dword ptr [esp + 0x48], edi
            //   897c244c             | mov                 dword ptr [esp + 0x4c], edi

        $sequence_9 = { 2bc2 3bc5 7705 e8???????? 85ed 7649 8b4c2424 }
            // n = 7, score = 100
            //   2bc2                 | sub                 eax, edx
            //   3bc5                 | cmp                 eax, ebp
            //   7705                 | ja                  7
            //   e8????????           |                     
            //   85ed                 | test                ebp, ebp
            //   7649                 | jbe                 0x4b
            //   8b4c2424             | mov                 ecx, dword ptr [esp + 0x24]

    condition:
        7 of them and filesize < 188416
}