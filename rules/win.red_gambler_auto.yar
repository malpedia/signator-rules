rule win_red_gambler_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.red_gambler."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.red_gambler"
        malpedia_rule_date = "20220405"
        malpedia_hash = "ecd38294bd47d5589be5cd5490dc8bb4804afc2a"
        malpedia_version = ""
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
        $sequence_0 = { 668985f0f8ffff ffd6 50 8d95f2f8ffff 68???????? 52 e8???????? }
            // n = 7, score = 400
            //   668985f0f8ffff       | mov                 word ptr [ebp - 0x710], ax
            //   ffd6                 | call                esi
            //   50                   | push                eax
            //   8d95f2f8ffff         | lea                 edx, dword ptr [ebp - 0x70e]
            //   68????????           |                     
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_1 = { 50 ffd2 85c0 7568 8b44240c 8b10 }
            // n = 6, score = 400
            //   50                   | push                eax
            //   ffd2                 | call                edx
            //   85c0                 | test                eax, eax
            //   7568                 | jne                 0x6a
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   8b10                 | mov                 edx, dword ptr [eax]

        $sequence_2 = { 7418 56 6a00 ff15???????? 50 ff15???????? 5f }
            // n = 7, score = 400
            //   7418                 | je                  0x1a
            //   56                   | push                esi
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   5f                   | pop                 edi

        $sequence_3 = { 83e4f8 81ec38020000 a1???????? 33c4 89842434020000 }
            // n = 5, score = 400
            //   83e4f8               | and                 esp, 0xfffffff8
            //   81ec38020000         | sub                 esp, 0x238
            //   a1????????           |                     
            //   33c4                 | xor                 eax, esp
            //   89842434020000       | mov                 dword ptr [esp + 0x234], eax

        $sequence_4 = { 46 ff4d0c 8bd1 75b1 5f 5e }
            // n = 6, score = 400
            //   46                   | inc                 esi
            //   ff4d0c               | dec                 dword ptr [ebp + 0xc]
            //   8bd1                 | mov                 edx, ecx
            //   75b1                 | jne                 0xffffffb3
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_5 = { 68???????? 50 89442424 ff15???????? 2b44241c 2b742418 }
            // n = 6, score = 400
            //   68????????           |                     
            //   50                   | push                eax
            //   89442424             | mov                 dword ptr [esp + 0x24], eax
            //   ff15????????         |                     
            //   2b44241c             | sub                 eax, dword ptr [esp + 0x1c]
            //   2b742418             | sub                 esi, dword ptr [esp + 0x18]

        $sequence_6 = { 8bec 56 8b7508 6a25 56 }
            // n = 5, score = 400
            //   8bec                 | mov                 ebp, esp
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   6a25                 | push                0x25
            //   56                   | push                esi

        $sequence_7 = { 57 7305 8b7d08 eb05 8b4508 }
            // n = 5, score = 400
            //   57                   | push                edi
            //   7305                 | jae                 7
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   eb05                 | jmp                 7
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_8 = { 8d8594fbffff 50 8d4d98 51 ff15???????? }
            // n = 5, score = 300
            //   8d8594fbffff         | lea                 eax, dword ptr [ebp - 0x46c]
            //   50                   | push                eax
            //   8d4d98               | lea                 ecx, dword ptr [ebp - 0x68]
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_9 = { 6a00 8d9598fbffff 52 68???????? 6a00 6a00 ff15???????? }
            // n = 7, score = 300
            //   6a00                 | push                0
            //   8d9598fbffff         | lea                 edx, dword ptr [ebp - 0x468]
            //   52                   | push                edx
            //   68????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_10 = { 6800010000 8d85fcfeffff 50 6a00 ff15???????? }
            // n = 5, score = 300
            //   6800010000           | push                0x100
            //   8d85fcfeffff         | lea                 eax, dword ptr [ebp - 0x104]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_11 = { 51 8d9598feffff 52 ff15???????? 8d8594fbffff }
            // n = 5, score = 300
            //   51                   | push                ecx
            //   8d9598feffff         | lea                 edx, dword ptr [ebp - 0x168]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8d8594fbffff         | lea                 eax, dword ptr [ebp - 0x46c]

        $sequence_12 = { 6800010000 8d8d98fdffff 51 8d9598feffff }
            // n = 4, score = 300
            //   6800010000           | push                0x100
            //   8d8d98fdffff         | lea                 ecx, dword ptr [ebp - 0x268]
            //   51                   | push                ecx
            //   8d9598feffff         | lea                 edx, dword ptr [ebp - 0x168]

        $sequence_13 = { 2f 2326 50 0f41631c 6a8c 44 e247 }
            // n = 7, score = 300
            //   2f                   | das                 
            //   2326                 | and                 esp, dword ptr [esi]
            //   50                   | push                eax
            //   0f41631c             | cmovno              esp, dword ptr [ebx + 0x1c]
            //   6a8c                 | push                -0x74
            //   44                   | inc                 esp
            //   e247                 | loop                0x49

        $sequence_14 = { 09afba55a367 59 2f 74be 6f }
            // n = 5, score = 300
            //   09afba55a367         | or                  dword ptr [edi + 0x67a355ba], ebp
            //   59                   | pop                 ecx
            //   2f                   | das                 
            //   74be                 | je                  0xffffffc0
            //   6f                   | outsd               dx, dword ptr [esi]

        $sequence_15 = { dc692c 64f33c87 3cfb 3ccd 047e 0000 }
            // n = 6, score = 300
            //   dc692c               | fsubr               qword ptr [ecx + 0x2c]
            //   64f33c87             | cmp                 al, 0x87
            //   3cfb                 | cmp                 al, 0xfb
            //   3ccd                 | cmp                 al, 0xcd
            //   047e                 | add                 al, 0x7e
            //   0000                 | add                 byte ptr [eax], al

        $sequence_16 = { 642827 3ccf 7bce 07 93 }
            // n = 5, score = 300
            // 
            //   3ccf                 | cmp                 al, 0xcf
            //   7bce                 | jnp                 0xffffffd0
            //   07                   | pop                 es
            //   93                   | xchg                eax, ebx

        $sequence_17 = { 6800010000 8d8dfcfdffff 51 6a00 }
            // n = 4, score = 300
            //   6800010000           | push                0x100
            //   8d8dfcfdffff         | lea                 ecx, dword ptr [ebp - 0x204]
            //   51                   | push                ecx
            //   6a00                 | push                0

        $sequence_18 = { 51 ff15???????? 83c414 6a00 6a00 8d9598fbffff }
            // n = 6, score = 300
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   83c414               | add                 esp, 0x14
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d9598fbffff         | lea                 edx, dword ptr [ebp - 0x468]

        $sequence_19 = { 68???????? 8d8d98fbffff 68???????? 51 ff15???????? }
            // n = 5, score = 300
            //   68????????           |                     
            //   8d8d98fbffff         | lea                 ecx, dword ptr [ebp - 0x468]
            //   68????????           |                     
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_20 = { f248 7456 7b78 cd50 }
            // n = 4, score = 300
            //   f248                 | dec                 eax
            //   7456                 | je                  0x58
            //   7b78                 | jnp                 0x7a
            //   cd50                 | int                 0x50

        $sequence_21 = { 2dc7dc1667 3663ea 7c0e 07 }
            // n = 4, score = 300
            //   2dc7dc1667           | sub                 eax, 0x6716dcc7
            //   3663ea               | arpl                dx, bp
            //   7c0e                 | jl                  0x10
            //   07                   | pop                 es

        $sequence_22 = { 7f6f c8603a0c 7364 42 }
            // n = 4, score = 300
            //   7f6f                 | jg                  0x71
            //   c8603a0c             | enter               0x3a60, 0xc
            //   7364                 | jae                 0x66
            //   42                   | inc                 edx

        $sequence_23 = { 8d5598 52 8d8598fdffff 50 68???????? }
            // n = 5, score = 300
            //   8d5598               | lea                 edx, dword ptr [ebp - 0x68]
            //   52                   | push                edx
            //   8d8598fdffff         | lea                 eax, dword ptr [ebp - 0x268]
            //   50                   | push                eax
            //   68????????           |                     

        $sequence_24 = { 3f 4f 7bac 6617 5e 3d067c263c }
            // n = 6, score = 300
            //   3f                   | aas                 
            //   4f                   | dec                 edi
            //   7bac                 | jnp                 0xffffffae
            //   6617                 | pop                 ss
            //   5e                   | pop                 esi
            //   3d067c263c           | cmp                 eax, 0x3c267c06

        $sequence_25 = { 8bec 33c0 8b4d08 3b0cc5d8694000 }
            // n = 4, score = 100
            //   8bec                 | mov                 ebp, esp
            //   33c0                 | xor                 eax, eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   3b0cc5d8694000       | cmp                 ecx, dword ptr [eax*8 + 0x4069d8]

        $sequence_26 = { 833cf5d481400001 751d 8d04f5d0814000 8938 68a00f0000 ff30 83c718 }
            // n = 7, score = 100
            //   833cf5d481400001     | cmp                 dword ptr [esi*8 + 0x4081d4], 1
            //   751d                 | jne                 0x1f
            //   8d04f5d0814000       | lea                 eax, dword ptr [esi*8 + 0x4081d0]
            //   8938                 | mov                 dword ptr [eax], edi
            //   68a00f0000           | push                0xfa0
            //   ff30                 | push                dword ptr [eax]
            //   83c718               | add                 edi, 0x18

        $sequence_27 = { 8d0445648e4000 8bc8 2bce 6a03 d1f9 68???????? 2bd9 }
            // n = 7, score = 100
            //   8d0445648e4000       | lea                 eax, dword ptr [eax*2 + 0x408e64]
            //   8bc8                 | mov                 ecx, eax
            //   2bce                 | sub                 ecx, esi
            //   6a03                 | push                3
            //   d1f9                 | sar                 ecx, 1
            //   68????????           |                     
            //   2bd9                 | sub                 ebx, ecx

        $sequence_28 = { ffd7 6800010000 8d95fcfeffff 52 }
            // n = 4, score = 100
            //   ffd7                 | call                edi
            //   6800010000           | push                0x100
            //   8d95fcfeffff         | lea                 edx, dword ptr [ebp - 0x104]
            //   52                   | push                edx

        $sequence_29 = { 762a 56 e8???????? 8d0445648e4000 8bc8 2bce }
            // n = 6, score = 100
            //   762a                 | jbe                 0x2c
            //   56                   | push                esi
            //   e8????????           |                     
            //   8d0445648e4000       | lea                 eax, dword ptr [eax*2 + 0x408e64]
            //   8bc8                 | mov                 ecx, eax
            //   2bce                 | sub                 ecx, esi

        $sequence_30 = { 8b7508 c7465c486b4000 83660800 33ff 47 897e14 }
            // n = 6, score = 100
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   c7465c486b4000       | mov                 dword ptr [esi + 0x5c], 0x406b48
            //   83660800             | and                 dword ptr [esi + 8], 0
            //   33ff                 | xor                 edi, edi
            //   47                   | inc                 edi
            //   897e14               | mov                 dword ptr [esi + 0x14], edi

        $sequence_31 = { 743d 8bf7 83e61f 8bc7 c1f805 c1e606 033485c0974000 }
            // n = 7, score = 100
            //   743d                 | je                  0x3f
            //   8bf7                 | mov                 esi, edi
            //   83e61f               | and                 esi, 0x1f
            //   8bc7                 | mov                 eax, edi
            //   c1f805               | sar                 eax, 5
            //   c1e606               | shl                 esi, 6
            //   033485c0974000       | add                 esi, dword ptr [eax*4 + 0x4097c0]

    condition:
        7 of them and filesize < 327680
}