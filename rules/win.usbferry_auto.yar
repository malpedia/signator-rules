rule win_usbferry_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.usbferry."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.usbferry"
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
        $sequence_0 = { c645ef73 c645f068 c645f15f c645f265 c645f36e c645f42e c645f565 }
            // n = 7, score = 200
            //   c645ef73             | mov                 byte ptr [ebp - 0x11], 0x73
            //   c645f068             | mov                 byte ptr [ebp - 0x10], 0x68
            //   c645f15f             | mov                 byte ptr [ebp - 0xf], 0x5f
            //   c645f265             | mov                 byte ptr [ebp - 0xe], 0x65
            //   c645f36e             | mov                 byte ptr [ebp - 0xd], 0x6e
            //   c645f42e             | mov                 byte ptr [ebp - 0xc], 0x2e
            //   c645f565             | mov                 byte ptr [ebp - 0xb], 0x65

        $sequence_1 = { 83c40c 33c0 e9???????? ff75e0 a1???????? }
            // n = 5, score = 200
            //   83c40c               | add                 esp, 0xc
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   ff75e0               | push                dword ptr [ebp - 0x20]
            //   a1????????           |                     

        $sequence_2 = { 807dfa01 750a 84db 0f94c0 83c011 eb0c }
            // n = 6, score = 200
            //   807dfa01             | cmp                 byte ptr [ebp - 6], 1
            //   750a                 | jne                 0xc
            //   84db                 | test                bl, bl
            //   0f94c0               | sete                al
            //   83c011               | add                 eax, 0x11
            //   eb0c                 | jmp                 0xe

        $sequence_3 = { 2bf1 e9???????? 8b44240c 83feff }
            // n = 4, score = 200
            //   2bf1                 | sub                 esi, ecx
            //   e9????????           |                     
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   83feff               | cmp                 esi, -1

        $sequence_4 = { e8???????? 8bf0 81fe00040000 0f876f010000 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   81fe00040000         | cmp                 esi, 0x400
            //   0f876f010000         | ja                  0x175

        $sequence_5 = { 6a00 68???????? 8d8538ffffff 6a01 50 8d55b8 }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   68????????           |                     
            //   8d8538ffffff         | lea                 eax, [ebp - 0xc8]
            //   6a01                 | push                1
            //   50                   | push                eax
            //   8d55b8               | lea                 edx, [ebp - 0x48]

        $sequence_6 = { a1???????? 33c5 8945fc 56 57 c645ec66 c645ed6c }
            // n = 7, score = 200
            //   a1????????           |                     
            //   33c5                 | xor                 eax, ebp
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   56                   | push                esi
            //   57                   | push                edi
            //   c645ec66             | mov                 byte ptr [ebp - 0x14], 0x66
            //   c645ed6c             | mov                 byte ptr [ebp - 0x13], 0x6c

        $sequence_7 = { eb36 0fb6450c 85c0 740f 6aff 8b8da0f7ffff }
            // n = 6, score = 200
            //   eb36                 | jmp                 0x38
            //   0fb6450c             | movzx               eax, byte ptr [ebp + 0xc]
            //   85c0                 | test                eax, eax
            //   740f                 | je                  0x11
            //   6aff                 | push                -1
            //   8b8da0f7ffff         | mov                 ecx, dword ptr [ebp - 0x860]

        $sequence_8 = { 51 ff15???????? 85c0 7422 c745d000000000 6afe 8d55f0 }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7422                 | je                  0x24
            //   c745d000000000       | mov                 dword ptr [ebp - 0x30], 0
            //   6afe                 | push                -2
            //   8d55f0               | lea                 edx, [ebp - 0x10]

        $sequence_9 = { 8bca 83e103 f3a4 6a01 8d85a8faffff }
            // n = 5, score = 200
            //   8bca                 | mov                 ecx, edx
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   6a01                 | push                1
            //   8d85a8faffff         | lea                 eax, [ebp - 0x558]

        $sequence_10 = { 50 a1???????? ff90b4000000 85c0 }
            // n = 4, score = 200
            //   50                   | push                eax
            //   a1????????           |                     
            //   ff90b4000000         | call                dword ptr [eax + 0xb4]
            //   85c0                 | test                eax, eax

        $sequence_11 = { 2bd0 7514 2bce 84db 740e }
            // n = 5, score = 200
            //   2bd0                 | sub                 edx, eax
            //   7514                 | jne                 0x16
            //   2bce                 | sub                 ecx, esi
            //   84db                 | test                bl, bl
            //   740e                 | je                  0x10

        $sequence_12 = { 8b45bc eb32 8b4de0 51 }
            // n = 4, score = 200
            //   8b45bc               | mov                 eax, dword ptr [ebp - 0x44]
            //   eb32                 | jmp                 0x34
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   51                   | push                ecx

        $sequence_13 = { 52 ff15???????? 8b85a4f7ffff 50 ff15???????? }
            // n = 5, score = 200
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8b85a4f7ffff         | mov                 eax, dword ptr [ebp - 0x85c]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_14 = { 5b eb21 0fb616 8bca 81e107000080 }
            // n = 5, score = 200
            //   5b                   | pop                 ebx
            //   eb21                 | jmp                 0x23
            //   0fb616               | movzx               edx, byte ptr [esi]
            //   8bca                 | mov                 ecx, edx
            //   81e107000080         | and                 ecx, 0x80000007

        $sequence_15 = { 6aff 8b8da0f7ffff 51 ff15???????? 8b95a0f7ffff }
            // n = 5, score = 200
            //   6aff                 | push                -1
            //   8b8da0f7ffff         | mov                 ecx, dword ptr [ebp - 0x860]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8b95a0f7ffff         | mov                 edx, dword ptr [ebp - 0x860]

    condition:
        7 of them and filesize < 638976
}