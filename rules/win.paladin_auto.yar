rule win_paladin_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.paladin."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.paladin"
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
        $sequence_0 = { 56 ff15???????? 85c0 752b 8b3f 8b1d???????? }
            // n = 6, score = 200
            //   56                   | push                esi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   752b                 | jne                 0x2d
            //   8b3f                 | mov                 edi, dword ptr [edi]
            //   8b1d????????         |                     

        $sequence_1 = { 88142b 43 ff15???????? 8bc8 8d742460 8bd1 8d3c2b }
            // n = 7, score = 200
            //   88142b               | mov                 byte ptr [ebx + ebp], dl
            //   43                   | inc                 ebx
            //   ff15????????         |                     
            //   8bc8                 | mov                 ecx, eax
            //   8d742460             | lea                 esi, [esp + 0x60]
            //   8bd1                 | mov                 edx, ecx
            //   8d3c2b               | lea                 edi, [ebx + ebp]

        $sequence_2 = { 7408 50 68???????? ffd7 8b44241c }
            // n = 5, score = 200
            //   7408                 | je                  0xa
            //   50                   | push                eax
            //   68????????           |                     
            //   ffd7                 | call                edi
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]

        $sequence_3 = { 53 894610 e8???????? 8b4c2444 83c438 894614 64890d00000000 }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   894610               | mov                 dword ptr [esi + 0x10], eax
            //   e8????????           |                     
            //   8b4c2444             | mov                 ecx, dword ptr [esp + 0x44]
            //   83c438               | add                 esp, 0x38
            //   894614               | mov                 dword ptr [esi + 0x14], eax
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx

        $sequence_4 = { a1???????? 85c0 7417 83f804 7412 83f805 }
            // n = 6, score = 200
            //   a1????????           |                     
            //   85c0                 | test                eax, eax
            //   7417                 | je                  0x19
            //   83f804               | cmp                 eax, 4
            //   7412                 | je                  0x14
            //   83f805               | cmp                 eax, 5

        $sequence_5 = { c645fc01 e8???????? 8b55dc a1???????? 85c2 0f84e2000000 8b35???????? }
            // n = 7, score = 200
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   e8????????           |                     
            //   8b55dc               | mov                 edx, dword ptr [ebp - 0x24]
            //   a1????????           |                     
            //   85c2                 | test                edx, eax
            //   0f84e2000000         | je                  0xe8
            //   8b35????????         |                     

        $sequence_6 = { 50 8b4344 51 50 ff15???????? 8b4e04 }
            // n = 6, score = 200
            //   50                   | push                eax
            //   8b4344               | mov                 eax, dword ptr [ebx + 0x44]
            //   51                   | push                ecx
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]

        $sequence_7 = { a1???????? 85c2 0f84e2000000 8b35???????? ffd3 56 }
            // n = 6, score = 200
            //   a1????????           |                     
            //   85c2                 | test                edx, eax
            //   0f84e2000000         | je                  0xe8
            //   8b35????????         |                     
            //   ffd3                 | call                ebx
            //   56                   | push                esi

        $sequence_8 = { 50 57 ff15???????? 8bf0 89b5acfeffff 85ff }
            // n = 6, score = 200
            //   50                   | push                eax
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   89b5acfeffff         | mov                 dword ptr [ebp - 0x154], esi
            //   85ff                 | test                edi, edi

        $sequence_9 = { 32c0 5e 81c484010000 c20800 85c0 }
            // n = 5, score = 200
            //   32c0                 | xor                 al, al
            //   5e                   | pop                 esi
            //   81c484010000         | add                 esp, 0x184
            //   c20800               | ret                 8
            //   85c0                 | test                eax, eax

    condition:
        7 of them and filesize < 106496
}