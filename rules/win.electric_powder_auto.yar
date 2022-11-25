rule win_electric_powder_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.electric_powder."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.electric_powder"
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
        $sequence_0 = { 8d0416 8b7314 8bf8 894508 83cf07 8975f8 3bf9 }
            // n = 7, score = 100
            //   8d0416               | lea                 eax, [esi + edx]
            //   8b7314               | mov                 esi, dword ptr [ebx + 0x14]
            //   8bf8                 | mov                 edi, eax
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   83cf07               | or                  edi, 7
            //   8975f8               | mov                 dword ptr [ebp - 8], esi
            //   3bf9                 | cmp                 edi, ecx

        $sequence_1 = { 83c418 8d85e8fbffff 3bc6 742f 8bc8 e8???????? 0f1006 }
            // n = 7, score = 100
            //   83c418               | add                 esp, 0x18
            //   8d85e8fbffff         | lea                 eax, [ebp - 0x418]
            //   3bc6                 | cmp                 eax, esi
            //   742f                 | je                  0x31
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   0f1006               | movups              xmm0, xmmword ptr [esi]

        $sequence_2 = { ffb5b4eeffff 51 8d8d98efffff e8???????? 83bdacefffff08 }
            // n = 5, score = 100
            //   ffb5b4eeffff         | push                dword ptr [ebp - 0x114c]
            //   51                   | push                ecx
            //   8d8d98efffff         | lea                 ecx, [ebp - 0x1068]
            //   e8????????           |                     
            //   83bdacefffff08       | cmp                 dword ptr [ebp - 0x1054], 8

        $sequence_3 = { 7407 50 ff15???????? 8d8e60010000 e8???????? }
            // n = 5, score = 100
            //   7407                 | je                  9
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d8e60010000         | lea                 ecx, [esi + 0x160]
            //   e8????????           |                     

        $sequence_4 = { 7553 8b49fc 3bc8 734c 2bc1 83f804 7245 }
            // n = 7, score = 100
            //   7553                 | jne                 0x55
            //   8b49fc               | mov                 ecx, dword ptr [ecx - 4]
            //   3bc8                 | cmp                 ecx, eax
            //   734c                 | jae                 0x4e
            //   2bc1                 | sub                 eax, ecx
            //   83f804               | cmp                 eax, 4
            //   7245                 | jb                  0x47

        $sequence_5 = { 50 725a 8b1e 53 57 e8???????? }
            // n = 6, score = 100
            //   50                   | push                eax
            //   725a                 | jb                  0x5c
            //   8b1e                 | mov                 ebx, dword ptr [esi]
            //   53                   | push                ebx
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_6 = { e9???????? 8d8d98faffff e9???????? 8d8db0faffff e9???????? 8d8d68faffff e9???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8d8d98faffff         | lea                 ecx, [ebp - 0x568]
            //   e9????????           |                     
            //   8d8db0faffff         | lea                 ecx, [ebp - 0x550]
            //   e9????????           |                     
            //   8d8d68faffff         | lea                 ecx, [ebp - 0x598]
            //   e9????????           |                     

        $sequence_7 = { 8d04c7 894604 8b45e4 8d0440 8d04c7 894608 8b4df4 }
            // n = 7, score = 100
            //   8d04c7               | lea                 eax, [edi + eax*8]
            //   894604               | mov                 dword ptr [esi + 4], eax
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   8d0440               | lea                 eax, [eax + eax*2]
            //   8d04c7               | lea                 eax, [edi + eax*8]
            //   894608               | mov                 dword ptr [esi + 8], eax
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_8 = { c747140f000000 68???????? c60700 e8???????? c645fc01 83c8ff 8b8decfbffff }
            // n = 7, score = 100
            //   c747140f000000       | mov                 dword ptr [edi + 0x14], 0xf
            //   68????????           |                     
            //   c60700               | mov                 byte ptr [edi], 0
            //   e8????????           |                     
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   83c8ff               | or                  eax, 0xffffffff
            //   8b8decfbffff         | mov                 ecx, dword ptr [ebp - 0x414]

        $sequence_9 = { 5e c60000 8bc2 8be5 5d c20800 6a03 }
            // n = 7, score = 100
            //   5e                   | pop                 esi
            //   c60000               | mov                 byte ptr [eax], 0
            //   8bc2                 | mov                 eax, edx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20800               | ret                 8
            //   6a03                 | push                3

    condition:
        7 of them and filesize < 565248
}