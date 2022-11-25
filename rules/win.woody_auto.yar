rule win_woody_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.woody."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.woody"
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
        $sequence_0 = { 0f86c8000000 8b542448 83c204 8b02 8b7c2444 8bf5 0d00000080 }
            // n = 7, score = 100
            //   0f86c8000000         | jbe                 0xce
            //   8b542448             | mov                 edx, dword ptr [esp + 0x48]
            //   83c204               | add                 edx, 4
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   8b7c2444             | mov                 edi, dword ptr [esp + 0x44]
            //   8bf5                 | mov                 esi, ebp
            //   0d00000080           | or                  eax, 0x80000000

        $sequence_1 = { 017804 015008 01580c 5f 5e 5b 8be5 }
            // n = 7, score = 100
            //   017804               | add                 dword ptr [eax + 4], edi
            //   015008               | add                 dword ptr [eax + 8], edx
            //   01580c               | add                 dword ptr [eax + 0xc], ebx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp

        $sequence_2 = { 8d542448 51 8d842414010000 52 8d4c243c 50 51 }
            // n = 7, score = 100
            //   8d542448             | lea                 edx, [esp + 0x48]
            //   51                   | push                ecx
            //   8d842414010000       | lea                 eax, [esp + 0x114]
            //   52                   | push                edx
            //   8d4c243c             | lea                 ecx, [esp + 0x3c]
            //   50                   | push                eax
            //   51                   | push                ecx

        $sequence_3 = { 3bfb 7412 56 53 ff55c4 8bf0 83fe05 }
            // n = 7, score = 100
            //   3bfb                 | cmp                 edi, ebx
            //   7412                 | je                  0x14
            //   56                   | push                esi
            //   53                   | push                ebx
            //   ff55c4               | call                dword ptr [ebp - 0x3c]
            //   8bf0                 | mov                 esi, eax
            //   83fe05               | cmp                 esi, 5

        $sequence_4 = { e8???????? 832700 59 8b8618010000 81c618010000 85c0 740a }
            // n = 7, score = 100
            //   e8????????           |                     
            //   832700               | and                 dword ptr [edi], 0
            //   59                   | pop                 ecx
            //   8b8618010000         | mov                 eax, dword ptr [esi + 0x118]
            //   81c618010000         | add                 esi, 0x118
            //   85c0                 | test                eax, eax
            //   740a                 | je                  0xc

        $sequence_5 = { 50 6824a60110 57 ffd5 83c9ff 33c0 83c40c }
            // n = 7, score = 100
            //   50                   | push                eax
            //   6824a60110           | push                0x1001a624
            //   57                   | push                edi
            //   ffd5                 | call                ebp
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   83c40c               | add                 esp, 0xc

        $sequence_6 = { 392e 7406 41 83c604 ebde 8b0c8a }
            // n = 6, score = 100
            //   392e                 | cmp                 dword ptr [esi], ebp
            //   7406                 | je                  8
            //   41                   | inc                 ecx
            //   83c604               | add                 esi, 4
            //   ebde                 | jmp                 0xffffffe0
            //   8b0c8a               | mov                 ecx, dword ptr [edx + ecx*4]

        $sequence_7 = { 51 53 8b44240c 55 56 33ed }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   55                   | push                ebp
            //   56                   | push                esi
            //   33ed                 | xor                 ebp, ebp

        $sequence_8 = { 3bc1 7419 85db 740d 8b38 893b 8b7804 }
            // n = 7, score = 100
            //   3bc1                 | cmp                 eax, ecx
            //   7419                 | je                  0x1b
            //   85db                 | test                ebx, ebx
            //   740d                 | je                  0xf
            //   8b38                 | mov                 edi, dword ptr [eax]
            //   893b                 | mov                 dword ptr [ebx], edi
            //   8b7804               | mov                 edi, dword ptr [eax + 4]

        $sequence_9 = { f3ab 66ab aa b940000000 33c0 8dbc24b8020000 896c2418 }
            // n = 7, score = 100
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al
            //   b940000000           | mov                 ecx, 0x40
            //   33c0                 | xor                 eax, eax
            //   8dbc24b8020000       | lea                 edi, [esp + 0x2b8]
            //   896c2418             | mov                 dword ptr [esp + 0x18], ebp

    condition:
        7 of them and filesize < 409600
}