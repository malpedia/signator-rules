rule win_sedll_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.sedll."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sedll"
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
        $sequence_0 = { ff15???????? 83c408 85c0 0f85ea000000 f30f6f05???????? 68d2010000 8d8424bc010000 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   0f85ea000000         | jne                 0xf0
            //   f30f6f05????????     |                     
            //   68d2010000           | push                0x1d2
            //   8d8424bc010000       | lea                 eax, [esp + 0x1bc]

        $sequence_1 = { 6aff 53 8b1d???????? 6a00 6a00 ffd3 }
            // n = 6, score = 200
            //   6aff                 | push                -1
            //   53                   | push                ebx
            //   8b1d????????         |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ffd3                 | call                ebx

        $sequence_2 = { 8d4c2410 6689442414 51 89442432 0f57c0 6689442436 }
            // n = 6, score = 200
            //   8d4c2410             | lea                 ecx, [esp + 0x10]
            //   6689442414           | mov                 word ptr [esp + 0x14], ax
            //   51                   | push                ecx
            //   89442432             | mov                 dword ptr [esp + 0x32], eax
            //   0f57c0               | xorps               xmm0, xmm0
            //   6689442436           | mov                 word ptr [esp + 0x36], ax

        $sequence_3 = { 895df4 50 ff75f0 895df8 ff15???????? 85c0 }
            // n = 6, score = 200
            //   895df4               | mov                 dword ptr [ebp - 0xc], ebx
            //   50                   | push                eax
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   895df8               | mov                 dword ptr [ebp - 8], ebx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_4 = { 73ef eb3e 8bd1 be???????? bf0c000000 }
            // n = 5, score = 200
            //   73ef                 | jae                 0xfffffff1
            //   eb3e                 | jmp                 0x40
            //   8bd1                 | mov                 edx, ecx
            //   be????????           |                     
            //   bf0c000000           | mov                 edi, 0xc

        $sequence_5 = { 51 56 ff500c 6800100000 6a40 ff15???????? }
            // n = 6, score = 200
            //   51                   | push                ecx
            //   56                   | push                esi
            //   ff500c               | call                dword ptr [eax + 0xc]
            //   6800100000           | push                0x1000
            //   6a40                 | push                0x40
            //   ff15????????         |                     

        $sequence_6 = { 8d3c4501000000 03f8 57 ff15???????? }
            // n = 4, score = 200
            //   8d3c4501000000       | lea                 edi, [eax*2 + 1]
            //   03f8                 | add                 edi, eax
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_7 = { 8bec 53 8b5d14 56 8b7510 57 8bfe }
            // n = 7, score = 200
            //   8bec                 | mov                 ebp, esp
            //   53                   | push                ebx
            //   8b5d14               | mov                 ebx, dword ptr [ebp + 0x14]
            //   56                   | push                esi
            //   8b7510               | mov                 esi, dword ptr [ebp + 0x10]
            //   57                   | push                edi
            //   8bfe                 | mov                 edi, esi

        $sequence_8 = { f7e6 b8398ee338 8bf2 d1ee 83c604 }
            // n = 5, score = 200
            //   f7e6                 | mul                 esi
            //   b8398ee338           | mov                 eax, 0x38e38e39
            //   8bf2                 | mov                 esi, edx
            //   d1ee                 | shr                 esi, 1
            //   83c604               | add                 esi, 4

        $sequence_9 = { 83c204 83ee04 73ef 8b4d08 85c9 7416 8b4510 }
            // n = 7, score = 200
            //   83c204               | add                 edx, 4
            //   83ee04               | sub                 esi, 4
            //   73ef                 | jae                 0xfffffff1
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   85c9                 | test                ecx, ecx
            //   7416                 | je                  0x18
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]

    condition:
        7 of them and filesize < 65536
}