rule win_cheesetray_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.cheesetray."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cheesetray"
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
        $sequence_0 = { 75f7 8d0c00 8d442428 50 52 e8???????? 83c408 }
            // n = 7, score = 200
            //   75f7                 | jne                 0xfffffff9
            //   8d0c00               | lea                 ecx, [eax + eax]
            //   8d442428             | lea                 eax, [esp + 0x28]
            //   50                   | push                eax
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_1 = { 7415 8b0b 8b5304 8d44241c 50 8b460c }
            // n = 6, score = 200
            //   7415                 | je                  0x17
            //   8b0b                 | mov                 ecx, dword ptr [ebx]
            //   8b5304               | mov                 edx, dword ptr [ebx + 4]
            //   8d44241c             | lea                 eax, [esp + 0x1c]
            //   50                   | push                eax
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]

        $sequence_2 = { 8b4508 51 8d542414 52 50 }
            // n = 5, score = 200
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   51                   | push                ecx
            //   8d542414             | lea                 edx, [esp + 0x14]
            //   52                   | push                edx
            //   50                   | push                eax

        $sequence_3 = { 8b4d08 8d855cf6ffff 50 51 b9a4090000 e8???????? }
            // n = 6, score = 200
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8d855cf6ffff         | lea                 eax, [ebp - 0x9a4]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   b9a4090000           | mov                 ecx, 0x9a4
            //   e8????????           |                     

        $sequence_4 = { 52 ffd6 8b45f4 5e 8be5 5d c3 }
            // n = 7, score = 200
            //   52                   | push                edx
            //   ffd6                 | call                esi
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   5e                   | pop                 esi
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 

        $sequence_5 = { 51 6a00 ffd7 85c0 8d842468010000 7416 8b742410 }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax
            //   8d842468010000       | lea                 eax, [esp + 0x168]
            //   7416                 | je                  0x18
            //   8b742410             | mov                 esi, dword ptr [esp + 0x10]

        $sequence_6 = { 85f6 7506 33c0 8bd8 eb5c a1???????? 8d5604 }
            // n = 7, score = 200
            //   85f6                 | test                esi, esi
            //   7506                 | jne                 8
            //   33c0                 | xor                 eax, eax
            //   8bd8                 | mov                 ebx, eax
            //   eb5c                 | jmp                 0x5e
            //   a1????????           |                     
            //   8d5604               | lea                 edx, [esi + 4]

        $sequence_7 = { 8d4da0 8d45fc 85d2 7402 8bc2 8d55ec 52 }
            // n = 7, score = 200
            //   8d4da0               | lea                 ecx, [ebp - 0x60]
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   85d2                 | test                edx, edx
            //   7402                 | je                  4
            //   8bc2                 | mov                 eax, edx
            //   8d55ec               | lea                 edx, [ebp - 0x14]
            //   52                   | push                edx

        $sequence_8 = { e8???????? 83c40c 5f 33c0 5b 5d c20c00 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   5f                   | pop                 edi
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c20c00               | ret                 0xc

        $sequence_9 = { 6a00 6a07 6800000080 50 83cfff 83cbff }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   6a07                 | push                7
            //   6800000080           | push                0x80000000
            //   50                   | push                eax
            //   83cfff               | or                  edi, 0xffffffff
            //   83cbff               | or                  ebx, 0xffffffff

    condition:
        7 of them and filesize < 8626176
}