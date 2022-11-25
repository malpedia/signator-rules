rule win_bleachgap_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.bleachgap."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bleachgap"
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
        $sequence_0 = { ff742424 45 e8???????? 8b5c2428 83c40c 3be8 0f8cf2feffff }
            // n = 7, score = 100
            //   ff742424             | push                dword ptr [esp + 0x24]
            //   45                   | inc                 ebp
            //   e8????????           |                     
            //   8b5c2428             | mov                 ebx, dword ptr [esp + 0x28]
            //   83c40c               | add                 esp, 0xc
            //   3be8                 | cmp                 ebp, eax
            //   0f8cf2feffff         | jl                  0xfffffef8

        $sequence_1 = { 8912 895208 50 c7410400000000 e8???????? 8d8ea4000000 8d83a4000000 }
            // n = 7, score = 100
            //   8912                 | mov                 dword ptr [edx], edx
            //   895208               | mov                 dword ptr [edx + 8], edx
            //   50                   | push                eax
            //   c7410400000000       | mov                 dword ptr [ecx + 4], 0
            //   e8????????           |                     
            //   8d8ea4000000         | lea                 ecx, [esi + 0xa4]
            //   8d83a4000000         | lea                 eax, [ebx + 0xa4]

        $sequence_2 = { e8???????? 83c40c 85c0 0f84cd000000 57 ff742444 8b7c2418 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   0f84cd000000         | je                  0xd3
            //   57                   | push                edi
            //   ff742444             | push                dword ptr [esp + 0x44]
            //   8b7c2418             | mov                 edi, dword ptr [esp + 0x18]

        $sequence_3 = { 8bc3 c1e818 330c8520bb5c00 0fb6c3 330c8520af5c00 8bc6 894a14 }
            // n = 7, score = 100
            //   8bc3                 | mov                 eax, ebx
            //   c1e818               | shr                 eax, 0x18
            //   330c8520bb5c00       | xor                 ecx, dword ptr [eax*4 + 0x5cbb20]
            //   0fb6c3               | movzx               eax, bl
            //   330c8520af5c00       | xor                 ecx, dword ptr [eax*4 + 0x5caf20]
            //   8bc6                 | mov                 eax, esi
            //   894a14               | mov                 dword ptr [edx + 0x14], ecx

        $sequence_4 = { 8d41f8 894411fc 8b02 8b4804 03ca 51 56 }
            // n = 7, score = 100
            //   8d41f8               | lea                 eax, [ecx - 8]
            //   894411fc             | mov                 dword ptr [ecx + edx - 4], eax
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   03ca                 | add                 ecx, edx
            //   51                   | push                ecx
            //   56                   | push                esi

        $sequence_5 = { c705????????01000000 c705????????01000000 6a04 58 6bc000 c7801479610002000000 6a04 }
            // n = 7, score = 100
            //   c705????????01000000     |     
            //   c705????????01000000     |     
            //   6a04                 | push                4
            //   58                   | pop                 eax
            //   6bc000               | imul                eax, eax, 0
            //   c7801479610002000000     | mov    dword ptr [eax + 0x617914], 2
            //   6a04                 | push                4

        $sequence_6 = { ffd0 8b4e20 84c0 740d 81f9bb010000 750d 8d4608 }
            // n = 7, score = 100
            //   ffd0                 | call                eax
            //   8b4e20               | mov                 ecx, dword ptr [esi + 0x20]
            //   84c0                 | test                al, al
            //   740d                 | je                  0xf
            //   81f9bb010000         | cmp                 ecx, 0x1bb
            //   750d                 | jne                 0xf
            //   8d4608               | lea                 eax, [esi + 8]

        $sequence_7 = { ff742438 ff742444 e8???????? 83c424 85c0 0f84f0000000 55 }
            // n = 7, score = 100
            //   ff742438             | push                dword ptr [esp + 0x38]
            //   ff742444             | push                dword ptr [esp + 0x44]
            //   e8????????           |                     
            //   83c424               | add                 esp, 0x24
            //   85c0                 | test                eax, eax
            //   0f84f0000000         | je                  0xf6
            //   55                   | push                ebp

        $sequence_8 = { 8b4dc4 83f908 7232 8b55b0 8d0c4d02000000 8bc2 81f900100000 }
            // n = 7, score = 100
            //   8b4dc4               | mov                 ecx, dword ptr [ebp - 0x3c]
            //   83f908               | cmp                 ecx, 8
            //   7232                 | jb                  0x34
            //   8b55b0               | mov                 edx, dword ptr [ebp - 0x50]
            //   8d0c4d02000000       | lea                 ecx, [ecx*2 + 2]
            //   8bc2                 | mov                 eax, edx
            //   81f900100000         | cmp                 ecx, 0x1000

        $sequence_9 = { 72f1 33c0 8b54241c eb09 8b87880f0000 8b04b0 85c0 }
            // n = 7, score = 100
            //   72f1                 | jb                  0xfffffff3
            //   33c0                 | xor                 eax, eax
            //   8b54241c             | mov                 edx, dword ptr [esp + 0x1c]
            //   eb09                 | jmp                 0xb
            //   8b87880f0000         | mov                 eax, dword ptr [edi + 0xf88]
            //   8b04b0               | mov                 eax, dword ptr [eax + esi*4]
            //   85c0                 | test                eax, eax

    condition:
        7 of them and filesize < 4538368
}