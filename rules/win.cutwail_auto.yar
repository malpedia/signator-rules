rule win_cutwail_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.cutwail."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cutwail"
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
        $sequence_0 = { 832700 83650c00 33db 3bf3 }
            // n = 4, score = 200
            //   832700               | and                 dword ptr [edi], 0
            //   83650c00             | and                 dword ptr [ebp + 0xc], 0
            //   33db                 | xor                 ebx, ebx
            //   3bf3                 | cmp                 esi, ebx

        $sequence_1 = { 80c36b 83c410 47 837d0c00 }
            // n = 4, score = 200
            //   80c36b               | add                 bl, 0x6b
            //   83c410               | add                 esp, 0x10
            //   47                   | inc                 edi
            //   837d0c00             | cmp                 dword ptr [ebp + 0xc], 0

        $sequence_2 = { 8b4508 8b00 2bc7 8d4408ff }
            // n = 4, score = 200
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   2bc7                 | sub                 eax, edi
            //   8d4408ff             | lea                 eax, [eax + ecx - 1]

        $sequence_3 = { 56 ff510c 85c0 7412 53 }
            // n = 5, score = 200
            //   56                   | push                esi
            //   ff510c               | call                dword ptr [ecx + 0xc]
            //   85c0                 | test                eax, eax
            //   7412                 | je                  0x14
            //   53                   | push                ebx

        $sequence_4 = { 7403 89702b 897514 8a455b }
            // n = 4, score = 200
            //   7403                 | je                  5
            //   89702b               | mov                 dword ptr [eax + 0x2b], esi
            //   897514               | mov                 dword ptr [ebp + 0x14], esi
            //   8a455b               | mov                 al, byte ptr [ebp + 0x5b]

        $sequence_5 = { 6880000000 ff750c 895d08 e8???????? 83c40c }
            // n = 5, score = 200
            //   6880000000           | push                0x80
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   895d08               | mov                 dword ptr [ebp + 8], ebx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_6 = { 6a00 8945fc 8d450c 6a00 }
            // n = 4, score = 200
            //   6a00                 | push                0
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8d450c               | lea                 eax, [ebp + 0xc]
            //   6a00                 | push                0

        $sequence_7 = { e8???????? 59 894558 395e21 740c }
            // n = 5, score = 200
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   894558               | mov                 dword ptr [ebp + 0x58], eax
            //   395e21               | cmp                 dword ptr [esi + 0x21], ebx
            //   740c                 | je                  0xe

    condition:
        7 of them and filesize < 262144
}