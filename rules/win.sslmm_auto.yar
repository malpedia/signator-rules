rule win_sslmm_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.sslmm."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sslmm"
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
        $sequence_0 = { 03f1 3bc5 750f 56 e8???????? 83c404 898370010000 }
            // n = 7, score = 400
            //   03f1                 | add                 esi, ecx
            //   3bc5                 | cmp                 eax, ebp
            //   750f                 | jne                 0x11
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   898370010000         | mov                 dword ptr [ebx + 0x170], eax

        $sequence_1 = { 8bcb e8???????? 83f8ff 0f84e4000000 e9???????? 3d21030900 c7837401000000000000 }
            // n = 7, score = 400
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   83f8ff               | cmp                 eax, -1
            //   0f84e4000000         | je                  0xea
            //   e9????????           |                     
            //   3d21030900           | cmp                 eax, 0x90321
            //   c7837401000000000000     | mov    dword ptr [ebx + 0x174], 0

        $sequence_2 = { 51 56 51 894c2454 ff15???????? 85c0 0f8423010000 }
            // n = 7, score = 400
            //   51                   | push                ecx
            //   56                   | push                esi
            //   51                   | push                ecx
            //   894c2454             | mov                 dword ptr [esp + 0x54], ecx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f8423010000         | je                  0x129

        $sequence_3 = { 83c404 85c0 0f849b000000 53 8d44241c }
            // n = 5, score = 400
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax
            //   0f849b000000         | je                  0xa1
            //   53                   | push                ebx
            //   8d44241c             | lea                 eax, [esp + 0x1c]

        $sequence_4 = { 53 6a10 53 681cc10000 51 53 52 }
            // n = 7, score = 400
            //   53                   | push                ebx
            //   6a10                 | push                0x10
            //   53                   | push                ebx
            //   681cc10000           | push                0xc11c
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   52                   | push                edx

        $sequence_5 = { 682c010000 68c8000000 6a00 ffd7 50 ffd3 8b86d0000000 }
            // n = 7, score = 400
            //   682c010000           | push                0x12c
            //   68c8000000           | push                0xc8
            //   6a00                 | push                0
            //   ffd7                 | call                edi
            //   50                   | push                eax
            //   ffd3                 | call                ebx
            //   8b86d0000000         | mov                 eax, dword ptr [esi + 0xd0]

        $sequence_6 = { 89bc2484000000 897c2468 897c2458 897c2450 }
            // n = 4, score = 400
            //   89bc2484000000       | mov                 dword ptr [esp + 0x84], edi
            //   897c2468             | mov                 dword ptr [esp + 0x68], edi
            //   897c2458             | mov                 dword ptr [esp + 0x58], edi
            //   897c2450             | mov                 dword ptr [esp + 0x50], edi

        $sequence_7 = { ff520c 83f8ff 899e64010000 7445 3bc3 }
            // n = 5, score = 400
            //   ff520c               | call                dword ptr [edx + 0xc]
            //   83f8ff               | cmp                 eax, -1
            //   899e64010000         | mov                 dword ptr [esi + 0x164], ebx
            //   7445                 | je                  0x47
            //   3bc3                 | cmp                 eax, ebx

        $sequence_8 = { 7508 83780405 7502 8bc8 83c00c 4e }
            // n = 6, score = 400
            //   7508                 | jne                 0xa
            //   83780405             | cmp                 dword ptr [eax + 4], 5
            //   7502                 | jne                 4
            //   8bc8                 | mov                 ecx, eax
            //   83c00c               | add                 eax, 0xc
            //   4e                   | dec                 esi

        $sequence_9 = { 83c404 40 50 53 6aff 57 6a00 }
            // n = 7, score = 400
            //   83c404               | add                 esp, 4
            //   40                   | inc                 eax
            //   50                   | push                eax
            //   53                   | push                ebx
            //   6aff                 | push                -1
            //   57                   | push                edi
            //   6a00                 | push                0

    condition:
        7 of them and filesize < 188416
}