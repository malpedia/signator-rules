rule win_microcin_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.microcin."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.microcin"
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
        $sequence_0 = { c744242880000000 c744242003000000 4533c9 ba00000080 448d4001 }
            // n = 5, score = 400
            //   c744242880000000     | mov                 ecx, dword ptr [ebp + 0x14]
            //   c744242003000000     | push                ecx
            //   4533c9               | push                0
            //   ba00000080           | push                0
            //   448d4001             | mov                 dword ptr [ebp - 0x14], eax

        $sequence_1 = { 897e04 5b 5f 5e 5d c20400 55 }
            // n = 7, score = 400
            //   897e04               | mov                 esp, ebp
            //   5b                   | pop                 ebp
            //   5f                   | mov                 esp, ebx
            //   5e                   | dec                 eax
            //   5d                   | xor                 eax, esp
            //   c20400               | dec                 eax
            //   55                   | mov                 dword ptr [ebp + 0x1b0], eax

        $sequence_2 = { 33f6 50 ffd3 85c0 7e18 80bc35a8feffff3a }
            // n = 6, score = 400
            //   33f6                 | push                0x104
            //   50                   | lea                 eax, dword ptr [ebp - 0x138]
            //   ffd3                 | push                0
            //   85c0                 | push                esi
            //   7e18                 | movzx               eax, ax
            //   80bc35a8feffff3a     | shl                 eax, 0x10

        $sequence_3 = { 4833c4 488985b0010000 488bd9 488d4c2458 ff15???????? }
            // n = 5, score = 400
            //   4833c4               | dec                 eax
            //   488985b0010000       | lea                 ecx, dword ptr [0x10c95]
            //   488bd9               | add                 esp, 8
            //   488d4c2458           | mov                 eax, dword ptr [ebp - 0x10]
            //   ff15????????         |                     

        $sequence_4 = { 4885c0 742b 488b4018 488b08 8b09 ff15???????? 488bf8 }
            // n = 7, score = 400
            //   4885c0               | push                0xd
            //   742b                 | pop                 eax
            //   488b4018             | pop                 ebp
            //   488b08               | ret                 
            //   8b09                 | mov                 eax, dword ptr [ecx*8 + 0x4131f4]
            //   ff15????????         |                     
            //   488bf8               | inc                 eax

        $sequence_5 = { 488bf8 488bc8 ff15???????? 85c0 740c 488bd7 }
            // n = 6, score = 400
            //   488bf8               | mov                 dword ptr [eax + 0x24], edx
            //   488bc8               | mov                 ecx, dword ptr [ebp - 0xc]
            //   ff15????????         |                     
            //   85c0                 | add                 ecx, 8
            //   740c                 | push                ecx
            //   488bd7               | mov                 edx, dword ptr [ebp + 8]

        $sequence_6 = { 6805100000 68ffff0000 56 8b35???????? ffd6 6a04 }
            // n = 6, score = 400
            //   6805100000           | add                 eax, 8
            //   68ffff0000           | push                eax
            //   56                   | mov                 ecx, dword ptr [ebp - 4]
            //   8b35????????         |                     
            //   ffd6                 | push                0x128
            //   6a04                 | lea                 eax, dword ptr [ebp - 0x134]

        $sequence_7 = { ff15???????? 4863c8 807c0d8f5c 7412 }
            // n = 4, score = 400
            //   ff15????????         |                     
            //   4863c8               | and                 eax, 2
            //   807c0d8f5c           | mov                 dword ptr [ebp - 0x10], eax
            //   7412                 | jne                 0x19

        $sequence_8 = { 8b1d???????? 8d85a8feffff 50 ffd3 }
            // n = 4, score = 400
            //   8b1d????????         |                     
            //   8d85a8feffff         | mov                 dword ptr [ecx + edx*4], eax
            //   50                   | mov                 dword ptr [edx + 0x24], 0
            //   ffd3                 | mov                 eax, dword ptr [ebp - 4]

        $sequence_9 = { 418900 4989b688000000 41c7868400000004000000 4533c9 33d2 }
            // n = 5, score = 400
            //   418900               | add                 byte ptr [edx + ecx*2], al
            //   4989b688000000       | inc                 eax
            //   41c7868400000004000000     | mov    edx, dword ptr [ecx + 0x24]
            //   4533c9               | add                 edx, 1
            //   33d2                 | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_10 = { 488bcb ff15???????? 488bcb ff15???????? 448bc0 }
            // n = 5, score = 400
            //   488bcb               | add                 al, ah
            //   ff15????????         |                     
            //   488bcb               | dec                 ecx
            //   ff15????????         |                     
            //   448bc0               | inc                 eax

        $sequence_11 = { c6840d8002000077 488d8d80020000 ff15???????? 4863c8 c6840d8002000075 }
            // n = 5, score = 400
            //   c6840d8002000077     | mov                 dword ptr [edx + 0x104], ecx
            //   488d8d80020000       | mov                 dword ptr [ebp - 0x84], 0
            //   ff15????????         |                     
            //   4863c8               | jmp                 0x1b
            //   c6840d8002000075     | mov                 eax, dword ptr [ebp - 0x84]

        $sequence_12 = { 8d45ac 50 6801000080 ff15???????? 85c0 }
            // n = 5, score = 400
            //   8d45ac               | push                eax
            //   50                   | push                esi
            //   6801000080           | push                0x10000003
            //   ff15????????         |                     
            //   85c0                 | push                edi

        $sequence_13 = { 56 ff15???????? 85c0 0f45f7 }
            // n = 4, score = 400
            //   56                   | movzx               eax, word ptr [ebp - 0x13e]
            //   ff15????????         |                     
            //   85c0                 | push                eax
            //   0f45f7               | movzx               eax, word ptr [ebp - 0x140]

        $sequence_14 = { 8d85f8feffff 6804010000 50 ff15???????? 8d85f8feffff 50 }
            // n = 6, score = 400
            //   8d85f8feffff         | push                0
            //   6804010000           | push                eax
            //   50                   | je                  0x3f
            //   ff15????????         |                     
            //   8d85f8feffff         | push                0x10
            //   50                   | lea                 eax, dword ptr [esp + 0x10]

        $sequence_15 = { 7e18 80bc35a8feffff3a 741f 8d85a8feffff }
            // n = 4, score = 400
            //   7e18                 | mov                 edx, dword ptr [ebp - 0x2084]
            //   80bc35a8feffff3a     | imul                edx, edx, 0x68
            //   741f                 | lea                 ecx, dword ptr [ebp + edx - 0x15f0]
            //   8d85a8feffff         | mov                 edx, dword ptr [ebp - 0x2088]

        $sequence_16 = { fa fa fa fa fa fa fa }
            // n = 7, score = 200
            //   fa                   | lea                 ecx, dword ptr [ebp + eax*2 - 0x44]
            //   fa                   | dec                 eax
            //   fa                   | mov                 eax, ecx
            //   fa                   | dec                 ecx
            //   fa                   | sub                 eax, ebp
            //   fa                   | dec                 esp
            //   fa                   | lea                 eax, dword ptr [0x112b7]

        $sequence_17 = { e8???????? 4c8d05b7120100 41b903000000 488d4c45bc }
            // n = 4, score = 200
            //   e8????????           |                     
            //   4c8d05b7120100       | dec                 ecx
            //   41b903000000         | mov                 edx, ebp
            //   488d4c45bc           | inc                 ecx

        $sequence_18 = { 6828010000 8d85ccfeffff 6a00 50 }
            // n = 4, score = 200
            //   6828010000           | cli                 
            //   8d85ccfeffff         | cli                 
            //   6a00                 | cli                 
            //   50                   | cli                 

        $sequence_19 = { 8b5124 83c201 8b45f4 895024 8b4df4 83c108 51 }
            // n = 7, score = 200
            //   8b5124               | cli                 
            //   83c201               | cli                 
            //   8b45f4               | cli                 
            //   895024               | cli                 
            //   8b4df4               | cli                 
            //   83c108               | cli                 
            //   51                   | cli                 

        $sequence_20 = { 488d15f8110100 41b810200100 488bcd e8???????? e9???????? 4533c9 }
            // n = 6, score = 200
            //   488d15f8110100       | lea                 edi, dword ptr [esp - 0x19]
            //   41b810200100         | test                eax, eax
            //   488bcd               | jne                 0x2e
            //   e8????????           |                     
            //   e9????????           |                     
            //   4533c9               | dec                 esp

        $sequence_21 = { e8???????? 83c408 8b45f0 83e002 8945f0 7511 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   83c408               | outsb               dx, byte ptr [esi]
            //   8b45f0               | jbe                 0x6c
            //   83e002               | jb                  0x71
            //   8945f0               | outsb               dx, byte ptr [esi]
            //   7511                 | insd                dword ptr es:[edi], dx

        $sequence_22 = { 488d0d950c0100 ff15???????? 4885c0 7419 }
            // n = 4, score = 200
            //   488d0d950c0100       | dec                 eax
            //   ff15????????         |                     
            //   4885c0               | lea                 ecx, dword ptr [0x10c95]
            //   7419                 | dec                 eax

        $sequence_23 = { 6a0d 58 5d c3 8b04cdf4314100 }
            // n = 5, score = 200
            //   6a0d                 | outsb               dx, byte ptr gs:[esi]
            //   58                   | je                  8
            //   5d                   | arpl                word ptr [ebx + 0x73], sp
            //   c3                   | jbe                 0x78
            //   8b04cdf4314100       | push                0x652e7473

        $sequence_24 = { ff15???????? 8945ec 8b4df0 e8???????? 68204e0000 8b55ec }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   8945ec               | mov                 dword ptr [ebp], eax
            //   8b4df0               | dec                 ecx
            //   e8????????           |                     
            //   68204e0000           | mov                 edi, dword ptr [eax + 0xa8]
            //   8b55ec               | dec                 ebp

        $sequence_25 = { 752a 4c8d0502130100 8bd7 498bcd e8???????? 85c0 7415 }
            // n = 7, score = 200
            //   752a                 | dec                 eax
            //   4c8d0502130100       | lea                 edx, dword ptr [0x111f8]
            //   8bd7                 | dec                 esp
            //   498bcd               | lea                 eax, dword ptr [0x11374]
            //   e8????????           |                     
            //   85c0                 | dec                 eax
            //   7415                 | mov                 ecx, ebp

        $sequence_26 = { ff15???????? 418d7c24e7 85c0 752a 4c8d0502130100 8bd7 }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   418d7c24e7           | test                eax, eax
            //   85c0                 | je                  0x1b
            //   752a                 | inc                 ecx
            //   4c8d0502130100       | lea                 edi, dword ptr [esp - 0x19]
            //   8bd7                 | test                eax, eax

        $sequence_27 = { 7370 696465726167656e 742e 657865 }
            // n = 4, score = 200
            //   7370                 | dec                 ecx
            //   696465726167656e     | push                ebx
            //   742e                 | push                ebx
            //   657865               | push                esi

        $sequence_28 = { 636373 7673 6873742e65 7865 }
            // n = 4, score = 200
            //   636373               | lea                 eax, dword ptr [0x112b7]
            //   7673                 | inc                 ecx
            //   6873742e65           | mov                 ecx, 3
            //   7865                 | dec                 eax

        $sequence_29 = { cc 4c8d056c120100 498bd4 488bcd }
            // n = 4, score = 200
            //   cc                   | mov                 edx, esp
            //   4c8d056c120100       | xor                 ecx, ecx
            //   498bd4               | dec                 esp
            //   488bcd               | lea                 eax, dword ptr [0x112b7]

        $sequence_30 = { 4c8d0574130100 488bcd 418bd4 e8???????? 33c9 85c0 }
            // n = 6, score = 200
            //   4c8d0574130100       | dec                 eax
            //   488bcd               | test                eax, eax
            //   418bd4               | dec                 esp
            //   e8????????           |                     
            //   33c9                 | mov                 eax, ebx
            //   85c0                 | dec                 ecx

        $sequence_31 = { 49 53 53 56 43 }
            // n = 5, score = 200
            //   49                   | inc                 ebp
            //   53                   | xor                 ecx, ecx
            //   53                   | dec                 ecx
            //   56                   | mov                 ecx, ebp
            //   43                   | dec                 esp

        $sequence_32 = { 4c8bc3 498bd4 488bcd e8???????? 85c0 751a 488d15f8110100 }
            // n = 7, score = 200
            //   4c8bc3               | push                ebx
            //   498bd4               | dec                 eax
            //   488bcd               | sub                 esp, 0x20
            //   e8????????           |                     
            //   85c0                 | mov                 ebx, ecx
            //   751a                 | dec                 eax
            //   488d15f8110100       | lea                 ecx, dword ptr [0x10c95]

        $sequence_33 = { 726f 6e 6d 656e 7400 }
            // n = 5, score = 200
            //   726f                 | lea                 edx, dword ptr [0x111f8]
            //   6e                   | inc                 ecx
            //   6d                   | mov                 eax, 0x12010
            //   656e                 | dec                 eax
            //   7400                 | mov                 ecx, ebp

        $sequence_34 = { 8b4d14 51 68???????? 6a00 6a00 ff15???????? }
            // n = 6, score = 200
            //   8b4d14               | imul                esp, dword ptr [ebp + 0x72], 0x6e656761
            //   51                   | je                  0x38
            //   68????????           |                     
            //   6a00                 | js                  0x72
            //   6a00                 | dec                 eax
            //   ff15????????         |                     

        $sequence_35 = { 8b5508 898a04010000 c7857cffffff00000000 eb0f 8b857cffffff }
            // n = 5, score = 200
            //   8b5508               | cli                 
            //   898a04010000         | cli                 
            //   c7857cffffff00000000     | cli    
            //   eb0f                 | cli                 
            //   8b857cffffff         | jae                 0x72

        $sequence_36 = { 03048a 8b957cdfffff 6bd268 8d8c1510eaffff 8b9578dfffff 890491 e9???????? }
            // n = 7, score = 200
            //   03048a               | inc                 ecx
            //   8b957cdfffff         | mov                 esp, eax
            //   6bd268               | inc                 ebp
            //   8d8c1510eaffff       | test                esp, esp
            //   8b9578dfffff         | jne                 0xd
            //   890491               | dec                 ecx
            //   e9????????           |                     

        $sequence_37 = { 40 00e0 49 40 00044a 40 }
            // n = 6, score = 200
            //   40                   | js                  0x6c
            //   00e0                 | dec                 ecx
            //   49                   | push                ebx
            //   40                   | push                ebx
            //   00044a               | push                esi
            //   40                   | inc                 ebx

        $sequence_38 = { 41 89c4 45 85e4 7508 }
            // n = 5, score = 100
            //   41                   | cli                 
            //   89c4                 | cli                 
            //   45                   | cli                 
            //   85e4                 | jb                  0x71
            //   7508                 | outsb               dx, byte ptr [esi]

        $sequence_39 = { 33c5 8945fc 6804010000 8d85c8feffff }
            // n = 4, score = 100
            //   33c5                 | int3                
            //   8945fc               | dec                 esp
            //   6804010000           | lea                 eax, dword ptr [0x1126c]
            //   8d85c8feffff         | dec                 ecx

        $sequence_40 = { 8bf0 85f6 0f8480000000 33c9 85f6 }
            // n = 5, score = 100
            //   8bf0                 | lea                 ecx, dword ptr [0x10c95]
            //   85f6                 | dec                 eax
            //   0f8480000000         | test                eax, eax
            //   33c9                 | je                  0x1e
            //   85f6                 | inc                 eax

        $sequence_41 = { 8d44243c 50 ffd3 8d44243c 50 ff15???????? }
            // n = 6, score = 100
            //   8d44243c             | lea                 eax, dword ptr [0x11374]
            //   50                   | dec                 eax
            //   ffd3                 | mov                 ecx, ebp
            //   8d44243c             | inc                 ecx
            //   50                   | mov                 edx, esp
            //   ff15????????         |                     

        $sequence_42 = { 743d 6a10 8d442410 50 56 6803000010 57 }
            // n = 7, score = 100
            //   743d                 | inc                 ecx
            //   6a10                 | mov                 eax, 0x12010
            //   8d442410             | dec                 eax
            //   50                   | mov                 ecx, ebp
            //   56                   | inc                 ecx
            //   6803000010           | mov                 esp, 0x314
            //   57                   | dec                 esp

        $sequence_43 = { 0fb785c2feffff 50 0fb785c0feffff 50 0fb785befeffff }
            // n = 5, score = 100
            //   0fb785c2feffff       | mov                 edx, esp
            //   50                   | dec                 eax
            //   0fb785c0feffff       | test                eax, eax
            //   50                   | je                  0x1e
            //   0fb785befeffff       | dec                 eax

        $sequence_44 = { 25ff0f0000 0306 50 ff7510 53 }
            // n = 5, score = 100
            //   25ff0f0000           | outsb               dx, byte ptr [esi]
            //   0306                 | jbe                 0x6b
            //   50                   | jb                  0x73
            //   ff7510               | outsb               dx, byte ptr [esi]
            //   53                   | insd                dword ptr es:[edi], dx

        $sequence_45 = { 6a00 56 ff15???????? 0fb7c0 c1e010 50 ff15???????? }
            // n = 7, score = 100
            //   6a00                 | mov                 edx, esp
            //   56                   | dec                 eax
            //   ff15????????         |                     
            //   0fb7c0               | mov                 ecx, ebp
            //   c1e010               | xor                 edx, edx
            //   50                   | xor                 ecx, ecx
            //   ff15????????         |                     

        $sequence_46 = { 48 894500 49 8bb8a8000000 4d }
            // n = 5, score = 100
            //   48                   | outsb               dx, byte ptr gs:[esi]
            //   894500               | je                  4
            //   49                   | cli                 
            //   8bb8a8000000         | cli                 
            //   4d                   | cli                 

        $sequence_47 = { 49 8b7520 4c 89e9 4c }
            // n = 5, score = 100
            //   49                   | insd                dword ptr es:[edi], dx
            //   8b7520               | outsb               dx, byte ptr gs:[esi]
            //   4c                   | je                  5
            //   89e9                 | jbe                 0x6b
            //   4c                   | jb                  0x73

        $sequence_48 = { 8d45f0 50 8d45fc 50 56 bf06000200 }
            // n = 6, score = 100
            //   8d45f0               | cli                 
            //   50                   | cli                 
            //   8d45fc               | outsb               dx, byte ptr [esi]
            //   50                   | insd                dword ptr es:[edi], dx
            //   56                   | outsb               dx, byte ptr gs:[esi]
            //   bf06000200           | je                  4

        $sequence_49 = { 6a01 8d442418 50 c744241c01000600 c744242000010000 89742424 ff15???????? }
            // n = 7, score = 100
            //   6a01                 | dec                 eax
            //   8d442418             | mov                 dword ptr [esp + 0x20], esi
            //   50                   | int3                
            //   c744241c01000600     | dec                 esp
            //   c744242000010000     | lea                 eax, dword ptr [0x1126c]
            //   89742424             | dec                 ecx
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 417792
}