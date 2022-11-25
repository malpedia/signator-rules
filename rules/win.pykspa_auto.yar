rule win_pykspa_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.pykspa."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pykspa"
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
        $sequence_0 = { 56 8b742408 85f6 7447 57 bf???????? 57 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   8b742408             | mov                 esi, dword ptr [esp + 8]
            //   85f6                 | test                esi, esi
            //   7447                 | je                  0x49
            //   57                   | push                edi
            //   bf????????           |                     
            //   57                   | push                edi

        $sequence_1 = { 41 4f 3bcf 76cc 8b451c 832000 8b4514 }
            // n = 7, score = 100
            //   41                   | inc                 ecx
            //   4f                   | dec                 edi
            //   3bcf                 | cmp                 ecx, edi
            //   76cc                 | jbe                 0xffffffce
            //   8b451c               | mov                 eax, dword ptr [ebp + 0x1c]
            //   832000               | and                 dword ptr [eax], 0
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]

        $sequence_2 = { 80f90d 8bfe 7417 8bc6 2bc3 80f90a }
            // n = 6, score = 100
            //   80f90d               | cmp                 cl, 0xd
            //   8bfe                 | mov                 edi, esi
            //   7417                 | je                  0x19
            //   8bc6                 | mov                 eax, esi
            //   2bc3                 | sub                 eax, ebx
            //   80f90a               | cmp                 cl, 0xa

        $sequence_3 = { 33c0 5f 5e 5b c3 56 8b35???????? }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   56                   | push                esi
            //   8b35????????         |                     

        $sequence_4 = { 8b45f0 017de8 3b4514 7c87 807dff00 751d ff45f8 }
            // n = 7, score = 100
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   017de8               | add                 dword ptr [ebp - 0x18], edi
            //   3b4514               | cmp                 eax, dword ptr [ebp + 0x14]
            //   7c87                 | jl                  0xffffff89
            //   807dff00             | cmp                 byte ptr [ebp - 1], 0
            //   751d                 | jne                 0x1f
            //   ff45f8               | inc                 dword ptr [ebp - 8]

        $sequence_5 = { 8d8500ffffff 50 56 ff15???????? 8d8500ffffff 68???????? 50 }
            // n = 7, score = 100
            //   8d8500ffffff         | lea                 eax, [ebp - 0x100]
            //   50                   | push                eax
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8d8500ffffff         | lea                 eax, [ebp - 0x100]
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_6 = { 8b1d???????? 807e2700 7522 8b4620 83f801 720b 6a06 }
            // n = 7, score = 100
            //   8b1d????????         |                     
            //   807e2700             | cmp                 byte ptr [esi + 0x27], 0
            //   7522                 | jne                 0x24
            //   8b4620               | mov                 eax, dword ptr [esi + 0x20]
            //   83f801               | cmp                 eax, 1
            //   720b                 | jb                  0xd
            //   6a06                 | push                6

        $sequence_7 = { 53 56 8b750c 8b460c 57 8b7d10 6a00 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]
            //   57                   | push                edi
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]
            //   6a00                 | push                0

        $sequence_8 = { 3d001a4f00 770b 837d0803 7205 885e24 eb04 c6462401 }
            // n = 7, score = 100
            //   3d001a4f00           | cmp                 eax, 0x4f1a00
            //   770b                 | ja                  0xd
            //   837d0803             | cmp                 dword ptr [ebp + 8], 3
            //   7205                 | jb                  7
            //   885e24               | mov                 byte ptr [esi + 0x24], bl
            //   eb04                 | jmp                 6
            //   c6462401             | mov                 byte ptr [esi + 0x24], 1

        $sequence_9 = { ff756c ff15???????? 85c0 0f8548feffff 33f6 ff756c ff15???????? }
            // n = 7, score = 100
            //   ff756c               | push                dword ptr [ebp + 0x6c]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f8548feffff         | jne                 0xfffffe4e
            //   33f6                 | xor                 esi, esi
            //   ff756c               | push                dword ptr [ebp + 0x6c]
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 835584
}