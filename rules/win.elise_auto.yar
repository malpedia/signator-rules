rule win_elise_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.elise."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.elise"
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
        $sequence_0 = { 894104 5e c3 53 56 }
            // n = 5, score = 400
            //   894104               | mov                 dword ptr [ecx + 4], eax
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_1 = { c645ff00 394d0c 770e 7205 }
            // n = 4, score = 400
            //   c645ff00             | mov                 byte ptr [ebp - 1], 0
            //   394d0c               | cmp                 dword ptr [ebp + 0xc], ecx
            //   770e                 | ja                  0x10
            //   7205                 | jb                  7

        $sequence_2 = { 8bc3 c1e310 0bc3 8d7e50 b980000000 }
            // n = 5, score = 400
            //   8bc3                 | mov                 eax, ebx
            //   c1e310               | shl                 ebx, 0x10
            //   0bc3                 | or                  eax, ebx
            //   8d7e50               | lea                 edi, [esi + 0x50]
            //   b980000000           | mov                 ecx, 0x80

        $sequence_3 = { 8d46c0 8945f0 83f804 0f8299000000 }
            // n = 4, score = 400
            //   8d46c0               | lea                 eax, [esi - 0x40]
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   83f804               | cmp                 eax, 4
            //   0f8299000000         | jb                  0x9f

        $sequence_4 = { c6410c01 e8???????? ff4c2410 8d7c7e01 75cf 8bc7 5f }
            // n = 7, score = 400
            //   c6410c01             | mov                 byte ptr [ecx + 0xc], 1
            //   e8????????           |                     
            //   ff4c2410             | dec                 dword ptr [esp + 0x10]
            //   8d7c7e01             | lea                 edi, [esi + edi*2 + 1]
            //   75cf                 | jne                 0xffffffd1
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi

        $sequence_5 = { 59 56 8bd8 33ff 57 53 895de0 }
            // n = 7, score = 400
            //   59                   | pop                 ecx
            //   56                   | push                esi
            //   8bd8                 | mov                 ebx, eax
            //   33ff                 | xor                 edi, edi
            //   57                   | push                edi
            //   53                   | push                ebx
            //   895de0               | mov                 dword ptr [ebp - 0x20], ebx

        $sequence_6 = { 7cf5 33c9 888f00010000 888f01010000 8bf7 }
            // n = 5, score = 400
            //   7cf5                 | jl                  0xfffffff7
            //   33c9                 | xor                 ecx, ecx
            //   888f00010000         | mov                 byte ptr [edi + 0x100], cl
            //   888f01010000         | mov                 byte ptr [edi + 0x101], cl
            //   8bf7                 | mov                 esi, edi

        $sequence_7 = { ab 75d2 5f 5e 5b c3 }
            // n = 6, score = 400
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   75d2                 | jne                 0xffffffd4
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c3                   | ret                 

        $sequence_8 = { 8d7e50 b980000000 f3ab 8bc2 0fb7d8 6a08 8bc3 }
            // n = 7, score = 400
            //   8d7e50               | lea                 edi, [esi + 0x50]
            //   b980000000           | mov                 ecx, 0x80
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8bc2                 | mov                 eax, edx
            //   0fb7d8               | movzx               ebx, ax
            //   6a08                 | push                8
            //   8bc3                 | mov                 eax, ebx

        $sequence_9 = { e8???????? 59 59 33c0 e9???????? 8b35???????? 6a04 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   8b35????????         |                     
            //   6a04                 | push                4

        $sequence_10 = { 8d4e01 81e1ff000080 7908 49 81c900ffffff 41 }
            // n = 6, score = 300
            //   8d4e01               | lea                 ecx, [esi + 1]
            //   81e1ff000080         | and                 ecx, 0x800000ff
            //   7908                 | jns                 0xa
            //   49                   | dec                 ecx
            //   81c900ffffff         | or                  ecx, 0xffffff00
            //   41                   | inc                 ecx

        $sequence_11 = { 8855ff 0fb6d2 03d7 81e2ff000080 7908 4a 81ca00ffffff }
            // n = 7, score = 300
            //   8855ff               | mov                 byte ptr [ebp - 1], dl
            //   0fb6d2               | movzx               edx, dl
            //   03d7                 | add                 edx, edi
            //   81e2ff000080         | and                 edx, 0x800000ff
            //   7908                 | jns                 0xa
            //   4a                   | dec                 edx
            //   81ca00ffffff         | or                  edx, 0xffffff00

        $sequence_12 = { 83ff08 0f82a1000000 8bd7 c1ea03 }
            // n = 4, score = 300
            //   83ff08               | cmp                 edi, 8
            //   0f82a1000000         | jb                  0xa7
            //   8bd7                 | mov                 edx, edi
            //   c1ea03               | shr                 edx, 3

        $sequence_13 = { 4a 81ca00ffffff 42 0fb6fa 8a1c07 881c06 }
            // n = 6, score = 300
            //   4a                   | dec                 edx
            //   81ca00ffffff         | or                  edx, 0xffffff00
            //   42                   | inc                 edx
            //   0fb6fa               | movzx               edi, dl
            //   8a1c07               | mov                 bl, byte ptr [edi + eax]
            //   881c06               | mov                 byte ptr [esi + eax], bl

        $sequence_14 = { 0f8566ffffff 5b 85ff 7415 0fb616 33d0 23d1 }
            // n = 7, score = 300
            //   0f8566ffffff         | jne                 0xffffff6c
            //   5b                   | pop                 ebx
            //   85ff                 | test                edi, edi
            //   7415                 | je                  0x17
            //   0fb616               | movzx               edx, byte ptr [esi]
            //   33d0                 | xor                 edx, eax
            //   23d1                 | and                 edx, ecx

        $sequence_15 = { 301f ff45f8 8b7df8 3b7d0c 0f8c7bffffff }
            // n = 5, score = 300
            //   301f                 | xor                 byte ptr [edi], bl
            //   ff45f8               | inc                 dword ptr [ebp - 8]
            //   8b7df8               | mov                 edi, dword ptr [ebp - 8]
            //   3b7d0c               | cmp                 edi, dword ptr [ebp + 0xc]
            //   0f8c7bffffff         | jl                  0xffffff81

    condition:
        7 of them and filesize < 204800
}