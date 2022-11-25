rule win_avzhan_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.avzhan."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.avzhan"
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
        $sequence_0 = { 6a00 ffd5 85c0 7410 68d0070000 ffd7 6a00 }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   ffd5                 | call                ebp
            //   85c0                 | test                eax, eax
            //   7410                 | je                  0x12
            //   68d0070000           | push                0x7d0
            //   ffd7                 | call                edi
            //   6a00                 | push                0

        $sequence_1 = { 50 56 ffd7 6a0a ffd3 ebdf 56 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   56                   | push                esi
            //   ffd7                 | call                edi
            //   6a0a                 | push                0xa
            //   ffd3                 | call                ebx
            //   ebdf                 | jmp                 0xffffffe1
            //   56                   | push                esi

        $sequence_2 = { 6a00 6a00 6a00 8d8c2418020000 6a00 }
            // n = 5, score = 200
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d8c2418020000       | lea                 ecx, [esp + 0x218]
            //   6a00                 | push                0

        $sequence_3 = { 6a00 8b542414 52 ffd3 }
            // n = 4, score = 200
            //   6a00                 | push                0
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   52                   | push                edx
            //   ffd3                 | call                ebx

        $sequence_4 = { 52 89742420 e8???????? 8bf8 6860ea0000 }
            // n = 5, score = 200
            //   52                   | push                edx
            //   89742420             | mov                 dword ptr [esp + 0x20], esi
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   6860ea0000           | push                0xea60

        $sequence_5 = { 8af2 83c408 8bc2 c1e010 668bc2 }
            // n = 5, score = 200
            //   8af2                 | mov                 dh, dl
            //   83c408               | add                 esp, 8
            //   8bc2                 | mov                 eax, edx
            //   c1e010               | shl                 eax, 0x10
            //   668bc2               | mov                 ax, dx

        $sequence_6 = { f3ab 8b442464 8b3d???????? 83c418 0bc6 8944244c 66c74424500000 }
            // n = 7, score = 200
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8b442464             | mov                 eax, dword ptr [esp + 0x64]
            //   8b3d????????         |                     
            //   83c418               | add                 esp, 0x18
            //   0bc6                 | or                  eax, esi
            //   8944244c             | mov                 dword ptr [esp + 0x4c], eax
            //   66c74424500000       | mov                 word ptr [esp + 0x50], 0

        $sequence_7 = { 66c74424500000 3935???????? 743c 8d542410 8d442420 52 50 }
            // n = 7, score = 200
            //   66c74424500000       | mov                 word ptr [esp + 0x50], 0
            //   3935????????         |                     
            //   743c                 | je                  0x3e
            //   8d542410             | lea                 edx, [esp + 0x10]
            //   8d442420             | lea                 eax, [esp + 0x20]
            //   52                   | push                edx
            //   50                   | push                eax

        $sequence_8 = { ff15???????? 50 ff15???????? e9???????? 68???????? 53 6801001f00 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   e9????????           |                     
            //   68????????           |                     
            //   53                   | push                ebx
            //   6801001f00           | push                0x1f0001

        $sequence_9 = { 8d8424ec000000 52 50 68???????? 8d8c2410020000 }
            // n = 5, score = 200
            //   8d8424ec000000       | lea                 eax, [esp + 0xec]
            //   52                   | push                edx
            //   50                   | push                eax
            //   68????????           |                     
            //   8d8c2410020000       | lea                 ecx, [esp + 0x210]

    condition:
        7 of them and filesize < 122880
}