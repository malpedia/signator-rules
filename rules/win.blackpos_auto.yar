rule win_blackpos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.blackpos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackpos"
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
        $sequence_0 = { 8906 8b07 894604 8b470c 8bd8 c1eb03 53 }
            // n = 7, score = 100
            //   8906                 | mov                 dword ptr [esi], eax
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   894604               | mov                 dword ptr [esi + 4], eax
            //   8b470c               | mov                 eax, dword ptr [edi + 0xc]
            //   8bd8                 | mov                 ebx, eax
            //   c1eb03               | shr                 ebx, 3
            //   53                   | push                ebx

        $sequence_1 = { 50 8d45c6 50 e8???????? 83c424 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   8d45c6               | lea                 eax, [ebp - 0x3a]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c424               | add                 esp, 0x24

        $sequence_2 = { 8d7de0 f3a5 a4 be00020000 }
            // n = 4, score = 100
            //   8d7de0               | lea                 edi, [ebp - 0x20]
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   a4                   | movsb               byte ptr es:[edi], byte ptr [esi]
            //   be00020000           | mov                 esi, 0x200

        $sequence_3 = { 50 8d85b0f4ffff 50 8d85b8f8ffff 50 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   8d85b0f4ffff         | lea                 eax, [ebp - 0xb50]
            //   50                   | push                eax
            //   8d85b8f8ffff         | lea                 eax, [ebp - 0x748]
            //   50                   | push                eax

        $sequence_4 = { 6a06 59 be???????? 8d7de0 f3a5 6a02 }
            // n = 6, score = 100
            //   6a06                 | push                6
            //   59                   | pop                 ecx
            //   be????????           |                     
            //   8d7de0               | lea                 edi, [ebp - 0x20]
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   6a02                 | push                2

        $sequence_5 = { e8???????? 83c40c 6a02 8d7ef1 68???????? 57 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a02                 | push                2
            //   8d7ef1               | lea                 edi, [esi - 0xf]
            //   68????????           |                     
            //   57                   | push                edi

        $sequence_6 = { 33f6 8935???????? ff15???????? 56 56 }
            // n = 5, score = 100
            //   33f6                 | xor                 esi, esi
            //   8935????????         |                     
            //   ff15????????         |                     
            //   56                   | push                esi
            //   56                   | push                esi

        $sequence_7 = { 750c 8b85dcfbffff 8985c4fbffff ff85dcfbffff ff8dc8fbffff 46 }
            // n = 6, score = 100
            //   750c                 | jne                 0xe
            //   8b85dcfbffff         | mov                 eax, dword ptr [ebp - 0x424]
            //   8985c4fbffff         | mov                 dword ptr [ebp - 0x43c], eax
            //   ff85dcfbffff         | inc                 dword ptr [ebp - 0x424]
            //   ff8dc8fbffff         | dec                 dword ptr [ebp - 0x438]
            //   46                   | inc                 esi

        $sequence_8 = { 8985f8fbffff 8b85d8fbffff 0385e4fbffff 6a1c }
            // n = 4, score = 100
            //   8985f8fbffff         | mov                 dword ptr [ebp - 0x408], eax
            //   8b85d8fbffff         | mov                 eax, dword ptr [ebp - 0x428]
            //   0385e4fbffff         | add                 eax, dword ptr [ebp - 0x41c]
            //   6a1c                 | push                0x1c

        $sequence_9 = { ffd6 85c0 7517 e8???????? eb10 8d45c4 50 }
            // n = 7, score = 100
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   7517                 | jne                 0x19
            //   e8????????           |                     
            //   eb10                 | jmp                 0x12
            //   8d45c4               | lea                 eax, [ebp - 0x3c]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 3293184
}