rule win_prikormka_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.prikormka."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prikormka"
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
        $sequence_0 = { 8d0446 50 e8???????? 83c40c 6a00 56 }
            // n = 6, score = 1600
            //   8d0446               | lea                 eax, [esi + eax*2]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a00                 | push                0
            //   56                   | push                esi

        $sequence_1 = { ffd3 85c0 7405 6a02 56 ffd5 }
            // n = 6, score = 1400
            //   ffd3                 | call                ebx
            //   85c0                 | test                eax, eax
            //   7405                 | je                  7
            //   6a02                 | push                2
            //   56                   | push                esi
            //   ffd5                 | call                ebp

        $sequence_2 = { 8d1446 52 e8???????? 83c40c }
            // n = 4, score = 1400
            //   8d1446               | lea                 edx, [esi + eax*2]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_3 = { 740e 68???????? 50 ff15???????? ffd0 }
            // n = 5, score = 1400
            //   740e                 | je                  0x10
            //   68????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   ffd0                 | call                eax

        $sequence_4 = { 6800020000 ff15???????? 68???????? ffd7 }
            // n = 4, score = 1400
            //   6800020000           | push                0x200
            //   ff15????????         |                     
            //   68????????           |                     
            //   ffd7                 | call                edi

        $sequence_5 = { 51 e8???????? 83c40c 68???????? ffd7 }
            // n = 5, score = 1400
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   68????????           |                     
            //   ffd7                 | call                edi

        $sequence_6 = { 6a00 56 ffd3 8b2d???????? 85c0 }
            // n = 5, score = 1400
            //   6a00                 | push                0
            //   56                   | push                esi
            //   ffd3                 | call                ebx
            //   8b2d????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_7 = { 7420 68???????? ffd7 03c0 }
            // n = 4, score = 1400
            //   7420                 | je                  0x22
            //   68????????           |                     
            //   ffd7                 | call                edi
            //   03c0                 | add                 eax, eax

        $sequence_8 = { 56 ffd3 85c0 7405 }
            // n = 4, score = 1400
            //   56                   | push                esi
            //   ffd3                 | call                ebx
            //   85c0                 | test                eax, eax
            //   7405                 | je                  7

        $sequence_9 = { 7408 41 42 3bce }
            // n = 4, score = 1000
            //   7408                 | je                  0xa
            //   41                   | inc                 ecx
            //   42                   | inc                 edx
            //   3bce                 | cmp                 ecx, esi

        $sequence_10 = { 83c40c 8d442404 50 ff15???????? 5e 85c0 }
            // n = 6, score = 1000
            //   83c40c               | add                 esp, 0xc
            //   8d442404             | lea                 eax, [esp + 4]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   5e                   | pop                 esi
            //   85c0                 | test                eax, eax

        $sequence_11 = { 7502 59 c3 50 ff15???????? }
            // n = 5, score = 1000
            //   7502                 | jne                 4
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_12 = { 68???????? 6a00 6a00 ff15???????? 85c0 7502 }
            // n = 6, score = 1000
            //   68????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7502                 | jne                 4

        $sequence_13 = { 5e 85c0 7422 68???????? 50 }
            // n = 5, score = 900
            //   5e                   | pop                 esi
            //   85c0                 | test                eax, eax
            //   7422                 | je                  0x24
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_14 = { ff15???????? ffd0 c705????????01000000 c705????????01000000 }
            // n = 4, score = 900
            //   ff15????????         |                     
            //   ffd0                 | call                eax
            //   c705????????01000000     |     
            //   c705????????01000000     |     

        $sequence_15 = { c3 57 6a00 6a00 6a00 6a02 }
            // n = 6, score = 900
            //   c3                   | ret                 
            //   57                   | push                edi
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a02                 | push                2

        $sequence_16 = { ff15???????? 0fb7c0 6683f805 7d09 }
            // n = 4, score = 900
            //   ff15????????         |                     
            //   0fb7c0               | movzx               eax, ax
            //   6683f805             | cmp                 ax, 5
            //   7d09                 | jge                 0xb

        $sequence_17 = { 83ec08 68???????? ff15???????? 0fb7c0 }
            // n = 4, score = 900
            //   83ec08               | sub                 esp, 8
            //   68????????           |                     
            //   ff15????????         |                     
            //   0fb7c0               | movzx               eax, ax

        $sequence_18 = { 5e 85c0 7414 c705????????01000000 }
            // n = 4, score = 700
            //   5e                   | pop                 esi
            //   85c0                 | test                eax, eax
            //   7414                 | je                  0x16
            //   c705????????01000000     |     

        $sequence_19 = { 33f6 e8???????? e8???????? e8???????? e8???????? e8???????? e8???????? }
            // n = 7, score = 700
            //   33f6                 | xor                 esi, esi
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     

        $sequence_20 = { 75f5 8b0d???????? 2bc2 8b15???????? d1f8 }
            // n = 5, score = 600
            //   75f5                 | jne                 0xfffffff7
            //   8b0d????????         |                     
            //   2bc2                 | sub                 eax, edx
            //   8b15????????         |                     
            //   d1f8                 | sar                 eax, 1

        $sequence_21 = { ff15???????? 3db7000000 751f 56 ff15???????? 33c0 }
            // n = 6, score = 600
            //   ff15????????         |                     
            //   3db7000000           | cmp                 eax, 0xb7
            //   751f                 | jne                 0x21
            //   56                   | push                esi
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax

        $sequence_22 = { 50 e8???????? 8b2d???????? 83c40c 6a00 }
            // n = 5, score = 600
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b2d????????         |                     
            //   83c40c               | add                 esp, 0xc
            //   6a00                 | push                0

        $sequence_23 = { 668b11 83c102 6685d2 75f5 2bce 8d1400 52 }
            // n = 7, score = 600
            //   668b11               | mov                 dx, word ptr [ecx]
            //   83c102               | add                 ecx, 2
            //   6685d2               | test                dx, dx
            //   75f5                 | jne                 0xfffffff7
            //   2bce                 | sub                 ecx, esi
            //   8d1400               | lea                 edx, [eax + eax]
            //   52                   | push                edx

        $sequence_24 = { 6a00 ff15???????? 8bf0 ff15???????? 3db7000000 751f }
            // n = 6, score = 600
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     
            //   3db7000000           | cmp                 eax, 0xb7
            //   751f                 | jne                 0x21

        $sequence_25 = { 8b35???????? 83c40c 68???????? ffd6 03c0 50 }
            // n = 6, score = 500
            //   8b35????????         |                     
            //   83c40c               | add                 esp, 0xc
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   03c0                 | add                 eax, eax
            //   50                   | push                eax

        $sequence_26 = { d1f8 8d7102 8da42400000000 668b11 83c102 }
            // n = 5, score = 500
            //   d1f8                 | sar                 eax, 1
            //   8d7102               | lea                 esi, [ecx + 2]
            //   8da42400000000       | lea                 esp, [esp]
            //   668b11               | mov                 dx, word ptr [ecx]
            //   83c102               | add                 ecx, 2

        $sequence_27 = { 50 e8???????? b8???????? 83c40c 8d5002 }
            // n = 5, score = 500
            //   50                   | push                eax
            //   e8????????           |                     
            //   b8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d5002               | lea                 edx, [eax + 2]

        $sequence_28 = { 8bd8 8d4b01 51 e8???????? 83c404 }
            // n = 5, score = 500
            //   8bd8                 | mov                 ebx, eax
            //   8d4b01               | lea                 ecx, [ebx + 1]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_29 = { 6685c9 75f5 2bc6 8d0c12 51 d1f8 }
            // n = 6, score = 500
            //   6685c9               | test                cx, cx
            //   75f5                 | jne                 0xfffffff7
            //   2bc6                 | sub                 eax, esi
            //   8d0c12               | lea                 ecx, [edx + edx]
            //   51                   | push                ecx
            //   d1f8                 | sar                 eax, 1

        $sequence_30 = { 85c0 7409 6a02 68???????? }
            // n = 4, score = 400
            //   85c0                 | test                eax, eax
            //   7409                 | je                  0xb
            //   6a02                 | push                2
            //   68????????           |                     

        $sequence_31 = { 83c40c 8d5002 668b08 83c002 6685c9 75f5 8b0d???????? }
            // n = 7, score = 400
            //   83c40c               | add                 esp, 0xc
            //   8d5002               | lea                 edx, [eax + 2]
            //   668b08               | mov                 cx, word ptr [eax]
            //   83c002               | add                 eax, 2
            //   6685c9               | test                cx, cx
            //   75f5                 | jne                 0xfffffff7
            //   8b0d????????         |                     

        $sequence_32 = { 75f5 2bc2 d1f8 8bd0 b8???????? }
            // n = 5, score = 300
            //   75f5                 | jne                 0xfffffff7
            //   2bc2                 | sub                 eax, edx
            //   d1f8                 | sar                 eax, 1
            //   8bd0                 | mov                 edx, eax
            //   b8????????           |                     

        $sequence_33 = { b9???????? d1f8 8d7102 668b11 83c102 6685d2 }
            // n = 6, score = 300
            //   b9????????           |                     
            //   d1f8                 | sar                 eax, 1
            //   8d7102               | lea                 esi, [ecx + 2]
            //   668b11               | mov                 dx, word ptr [ecx]
            //   83c102               | add                 ecx, 2
            //   6685d2               | test                dx, dx

        $sequence_34 = { 75f5 2bc6 03d2 52 }
            // n = 4, score = 300
            //   75f5                 | jne                 0xfffffff7
            //   2bc6                 | sub                 eax, esi
            //   03d2                 | add                 edx, edx
            //   52                   | push                edx

        $sequence_35 = { 56 57 68???????? 33ff 57 57 ff15???????? }
            // n = 7, score = 300
            //   56                   | push                esi
            //   57                   | push                edi
            //   68????????           |                     
            //   33ff                 | xor                 edi, edi
            //   57                   | push                edi
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_36 = { e8???????? 83c40c eb0d 6a00 6800020000 }
            // n = 5, score = 300
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   eb0d                 | jmp                 0xf
            //   6a00                 | push                0
            //   6800020000           | push                0x200

        $sequence_37 = { 83c40c 68???????? ffd6 50 68???????? 57 }
            // n = 6, score = 300
            //   83c40c               | add                 esp, 0xc
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   50                   | push                eax
            //   68????????           |                     
            //   57                   | push                edi

        $sequence_38 = { 83c102 6685d2 75f5 8d1400 2bce 52 }
            // n = 6, score = 300
            //   83c102               | add                 ecx, 2
            //   6685d2               | test                dx, dx
            //   75f5                 | jne                 0xfffffff7
            //   8d1400               | lea                 edx, [eax + eax]
            //   2bce                 | sub                 ecx, esi
            //   52                   | push                edx

        $sequence_39 = { 68???????? 57 ffd6 03c7 50 e8???????? 83c40c }
            // n = 7, score = 300
            //   68????????           |                     
            //   57                   | push                edi
            //   ffd6                 | call                esi
            //   03c7                 | add                 eax, edi
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_40 = { b8???????? 8d7002 8da42400000000 668b08 83c002 }
            // n = 5, score = 300
            //   b8????????           |                     
            //   8d7002               | lea                 esi, [eax + 2]
            //   8da42400000000       | lea                 esp, [esp]
            //   668b08               | mov                 cx, word ptr [eax]
            //   83c002               | add                 eax, 2

        $sequence_41 = { 8b3d???????? 85f6 7420 68???????? }
            // n = 4, score = 300
            //   8b3d????????         |                     
            //   85f6                 | test                esi, esi
            //   7420                 | je                  0x22
            //   68????????           |                     

        $sequence_42 = { 85c0 756a ff7708 e8???????? }
            // n = 4, score = 100
            //   85c0                 | test                eax, eax
            //   756a                 | jne                 0x6c
            //   ff7708               | push                dword ptr [edi + 8]
            //   e8????????           |                     

        $sequence_43 = { 6a17 59 83ec5c 6a17 8bf3 }
            // n = 5, score = 100
            //   6a17                 | push                0x17
            //   59                   | pop                 ecx
            //   83ec5c               | sub                 esp, 0x5c
            //   6a17                 | push                0x17
            //   8bf3                 | mov                 esi, ebx

        $sequence_44 = { 89758c 56 be???????? 56 e8???????? 68???????? }
            // n = 6, score = 100
            //   89758c               | mov                 dword ptr [ebp - 0x74], esi
            //   56                   | push                esi
            //   be????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   68????????           |                     

        $sequence_45 = { e8???????? 8b4508 83c41c 5f c9 c3 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83c41c               | add                 esp, 0x1c
            //   5f                   | pop                 edi
            //   c9                   | leave               
            //   c3                   | ret                 

    condition:
        7 of them and filesize < 401408
}