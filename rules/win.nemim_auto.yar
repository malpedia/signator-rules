rule win_nemim_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.nemim."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nemim"
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
        $sequence_0 = { 8bc1 c1f805 8d3c8540604300 8bc1 83e01f 8d34c0 }
            // n = 6, score = 200
            //   8bc1                 | mov                 eax, ecx
            //   c1f805               | sar                 eax, 5
            //   8d3c8540604300       | lea                 edi, [eax*4 + 0x436040]
            //   8bc1                 | mov                 eax, ecx
            //   83e01f               | and                 eax, 0x1f
            //   8d34c0               | lea                 esi, [eax + eax*8]

        $sequence_1 = { c705????????00000000 eb17 83fd0a 7c0c c705????????00000000 eb06 892d???????? }
            // n = 7, score = 200
            //   c705????????00000000     |     
            //   eb17                 | jmp                 0x19
            //   83fd0a               | cmp                 ebp, 0xa
            //   7c0c                 | jl                  0xe
            //   c705????????00000000     |     
            //   eb06                 | jmp                 8
            //   892d????????         |                     

        $sequence_2 = { 56 ff15???????? 8b442410 3d97010000 0f84ae000000 6800040000 }
            // n = 6, score = 200
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   3d97010000           | cmp                 eax, 0x197
            //   0f84ae000000         | je                  0xb4
            //   6800040000           | push                0x400

        $sequence_3 = { f3a4 8b742410 45 83c604 83c304 89742410 e9???????? }
            // n = 7, score = 200
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8b742410             | mov                 esi, dword ptr [esp + 0x10]
            //   45                   | inc                 ebp
            //   83c604               | add                 esi, 4
            //   83c304               | add                 ebx, 4
            //   89742410             | mov                 dword ptr [esp + 0x10], esi
            //   e9????????           |                     

        $sequence_4 = { 48 83f81e 770e 0fb680efa94000 ff2485cfa94000 }
            // n = 5, score = 200
            //   48                   | dec                 eax
            //   83f81e               | cmp                 eax, 0x1e
            //   770e                 | ja                  0x10
            //   0fb680efa94000       | movzx               eax, byte ptr [eax + 0x40a9ef]
            //   ff2485cfa94000       | jmp                 dword ptr [eax*4 + 0x40a9cf]

        $sequence_5 = { 33d2 8a50fa 83c604 c1e108 0bca 4f }
            // n = 6, score = 200
            //   33d2                 | xor                 edx, edx
            //   8a50fa               | mov                 dl, byte ptr [eax - 6]
            //   83c604               | add                 esi, 4
            //   c1e108               | shl                 ecx, 8
            //   0bca                 | or                  ecx, edx
            //   4f                   | dec                 edi

        $sequence_6 = { c746543f3f4200 7531 6a40 e8???????? 59 }
            // n = 5, score = 200
            //   c746543f3f4200       | mov                 dword ptr [esi + 0x54], 0x423f3f
            //   7531                 | jne                 0x33
            //   6a40                 | push                0x40
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_7 = { 85ff 0f84a2000000 33f6 57 e8???????? 83c404 }
            // n = 6, score = 200
            //   85ff                 | test                edi, edi
            //   0f84a2000000         | je                  0xa8
            //   33f6                 | xor                 esi, esi
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_8 = { 0f8540010000 68???????? 68???????? c744241c01000000 e8???????? 83c408 }
            // n = 6, score = 200
            //   0f8540010000         | jne                 0x146
            //   68????????           |                     
            //   68????????           |                     
            //   c744241c01000000     | mov                 dword ptr [esp + 0x1c], 1
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_9 = { 8844244c e8???????? 68???????? e8???????? 68???????? 8bf0 }
            // n = 6, score = 200
            //   8844244c             | mov                 byte ptr [esp + 0x4c], al
            //   e8????????           |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   68????????           |                     
            //   8bf0                 | mov                 esi, eax

    condition:
        7 of them and filesize < 499712
}