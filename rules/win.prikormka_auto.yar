rule win_prikormka_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.prikormka."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prikormka"
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
        $sequence_0 = { 8d0446 50 e8???????? 83c40c 6a00 }
            // n = 5, score = 1600
            //   8d0446               | lea                 eax, dword ptr [esi + eax*2]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a00                 | push                0

        $sequence_1 = { 85f6 7420 68???????? ffd7 }
            // n = 4, score = 1400
            //   85f6                 | test                esi, esi
            //   7420                 | je                  0x22
            //   68????????           |                     
            //   ffd7                 | call                edi

        $sequence_2 = { 8d1446 52 e8???????? 83c40c }
            // n = 4, score = 1400
            //   8d1446               | lea                 edx, dword ptr [esi + eax*2]
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

        $sequence_4 = { 83c40c 68???????? ffd7 03c0 50 68???????? 56 }
            // n = 7, score = 1400
            //   83c40c               | add                 esp, 0xc
            //   68????????           |                     
            //   ffd7                 | call                edi
            //   03c0                 | add                 eax, eax
            //   50                   | push                eax
            //   68????????           |                     
            //   56                   | push                esi

        $sequence_5 = { e8???????? 8b1d???????? 83c40c 6a00 56 ffd3 }
            // n = 6, score = 1400
            //   e8????????           |                     
            //   8b1d????????         |                     
            //   83c40c               | add                 esp, 0xc
            //   6a00                 | push                0
            //   56                   | push                esi
            //   ffd3                 | call                ebx

        $sequence_6 = { 6a00 56 ffd3 85c0 7405 6a02 }
            // n = 6, score = 1400
            //   6a00                 | push                0
            //   56                   | push                esi
            //   ffd3                 | call                ebx
            //   85c0                 | test                eax, eax
            //   7405                 | je                  7
            //   6a02                 | push                2

        $sequence_7 = { 6800020000 ff15???????? 68???????? ffd7 }
            // n = 4, score = 1400
            //   6800020000           | push                0x200
            //   ff15????????         |                     
            //   68????????           |                     
            //   ffd7                 | call                edi

        $sequence_8 = { ffd3 8b2d???????? 85c0 7405 6a02 56 ffd5 }
            // n = 7, score = 1400
            //   ffd3                 | call                ebx
            //   8b2d????????         |                     
            //   85c0                 | test                eax, eax
            //   7405                 | je                  7
            //   6a02                 | push                2
            //   56                   | push                esi
            //   ffd5                 | call                ebp

        $sequence_9 = { 52 ffd6 03c0 50 }
            // n = 4, score = 1200
            //   52                   | push                edx
            //   ffd6                 | call                esi
            //   03c0                 | add                 eax, eax
            //   50                   | push                eax

        $sequence_10 = { 7408 41 42 3bce }
            // n = 4, score = 1000
            //   7408                 | je                  0xa
            //   41                   | inc                 ecx
            //   42                   | inc                 edx
            //   3bce                 | cmp                 ecx, esi

        $sequence_11 = { 6a00 6a00 ff15???????? 85c0 7502 59 c3 }
            // n = 7, score = 1000
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7502                 | jne                 4
            //   59                   | pop                 ecx
            //   c3                   | ret                 

        $sequence_12 = { e8???????? 83c40c 8d442404 50 ff15???????? 5e 85c0 }
            // n = 7, score = 1000
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d442404             | lea                 eax, dword ptr [esp + 4]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   5e                   | pop                 esi
            //   85c0                 | test                eax, eax

        $sequence_13 = { 7502 59 c3 50 ff15???????? b801000000 }
            // n = 6, score = 1000
            //   7502                 | jne                 4
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   50                   | push                eax
            //   ff15????????         |                     
            //   b801000000           | mov                 eax, 1

        $sequence_14 = { ff15???????? ffd0 c705????????01000000 c705????????01000000 }
            // n = 4, score = 900
            //   ff15????????         |                     
            //   ffd0                 | call                eax
            //   c705????????01000000     |     
            //   c705????????01000000     |     

        $sequence_15 = { 5e 85c0 7422 68???????? 50 }
            // n = 5, score = 900
            //   5e                   | pop                 esi
            //   85c0                 | test                eax, eax
            //   7422                 | je                  0x24
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_16 = { c3 57 6a00 6a00 6a00 6a02 }
            // n = 6, score = 900
            //   c3                   | ret                 
            //   57                   | push                edi
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a02                 | push                2

        $sequence_17 = { 83ec08 68???????? ff15???????? 0fb7c0 6683f805 7d09 }
            // n = 6, score = 900
            //   83ec08               | sub                 esp, 8
            //   68????????           |                     
            //   ff15????????         |                     
            //   0fb7c0               | movzx               eax, ax
            //   6683f805             | cmp                 ax, 5
            //   7d09                 | jge                 0xb

        $sequence_18 = { 3db7000000 750e 56 ff15???????? 33c0 5e }
            // n = 6, score = 700
            //   3db7000000           | cmp                 eax, 0xb7
            //   750e                 | jne                 0x10
            //   56                   | push                esi
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi

        $sequence_19 = { 33f6 e8???????? e8???????? e8???????? e8???????? e8???????? e8???????? }
            // n = 7, score = 700
            //   33f6                 | xor                 esi, esi
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     

        $sequence_20 = { 5e 85c0 7414 c705????????01000000 c705????????01000000 }
            // n = 5, score = 700
            //   5e                   | pop                 esi
            //   85c0                 | test                eax, eax
            //   7414                 | je                  0x16
            //   c705????????01000000     |     
            //   c705????????01000000     |     

        $sequence_21 = { 668b11 83c102 6685d2 75f5 2bce 8d1400 }
            // n = 6, score = 600
            //   668b11               | mov                 dx, word ptr [ecx]
            //   83c102               | add                 ecx, 2
            //   6685d2               | test                dx, dx
            //   75f5                 | jne                 0xfffffff7
            //   2bce                 | sub                 ecx, esi
            //   8d1400               | lea                 edx, dword ptr [eax + eax]

        $sequence_22 = { 2bce 8d1400 52 d1f9 }
            // n = 4, score = 600
            //   2bce                 | sub                 ecx, esi
            //   8d1400               | lea                 edx, dword ptr [eax + eax]
            //   52                   | push                edx
            //   d1f9                 | sar                 ecx, 1

        $sequence_23 = { 75f5 8b0d???????? 2bc2 8b15???????? d1f8 }
            // n = 5, score = 600
            //   75f5                 | jne                 0xfffffff7
            //   8b0d????????         |                     
            //   2bc2                 | sub                 eax, edx
            //   8b15????????         |                     
            //   d1f8                 | sar                 eax, 1

        $sequence_24 = { 8bf0 ff15???????? 3db7000000 751f 56 }
            // n = 5, score = 600
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     
            //   3db7000000           | cmp                 eax, 0xb7
            //   751f                 | jne                 0x21
            //   56                   | push                esi

        $sequence_25 = { 2bc6 8d0c12 51 d1f8 }
            // n = 4, score = 500
            //   2bc6                 | sub                 eax, esi
            //   8d0c12               | lea                 ecx, dword ptr [edx + edx]
            //   51                   | push                ecx
            //   d1f8                 | sar                 eax, 1

        $sequence_26 = { d1f8 8d7102 8da42400000000 668b11 }
            // n = 4, score = 500
            //   d1f8                 | sar                 eax, 1
            //   8d7102               | lea                 esi, dword ptr [ecx + 2]
            //   8da42400000000       | lea                 esp, dword ptr [esp]
            //   668b11               | mov                 dx, word ptr [ecx]

        $sequence_27 = { e8???????? 8b35???????? 83c40c 68???????? ffd6 03c0 }
            // n = 6, score = 500
            //   e8????????           |                     
            //   8b35????????         |                     
            //   83c40c               | add                 esp, 0xc
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   03c0                 | add                 eax, eax

        $sequence_28 = { ff15???????? 8bd8 8d4b01 51 e8???????? 83c404 }
            // n = 6, score = 500
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax
            //   8d4b01               | lea                 ecx, dword ptr [ebx + 1]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_29 = { 50 e8???????? b8???????? 83c40c 8d5002 }
            // n = 5, score = 500
            //   50                   | push                eax
            //   e8????????           |                     
            //   b8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d5002               | lea                 edx, dword ptr [eax + 2]

        $sequence_30 = { 83c40c 8d5002 668b08 83c002 6685c9 75f5 8b0d???????? }
            // n = 7, score = 400
            //   83c40c               | add                 esp, 0xc
            //   8d5002               | lea                 edx, dword ptr [eax + 2]
            //   668b08               | mov                 cx, word ptr [eax]
            //   83c002               | add                 eax, 2
            //   6685c9               | test                cx, cx
            //   75f5                 | jne                 0xfffffff7
            //   8b0d????????         |                     

        $sequence_31 = { 85c0 7409 6a02 68???????? }
            // n = 4, score = 400
            //   85c0                 | test                eax, eax
            //   7409                 | je                  0xb
            //   6a02                 | push                2
            //   68????????           |                     

        $sequence_32 = { d1f8 8bd0 b8???????? 8d7002 8da42400000000 668b08 83c002 }
            // n = 7, score = 300
            //   d1f8                 | sar                 eax, 1
            //   8bd0                 | mov                 edx, eax
            //   b8????????           |                     
            //   8d7002               | lea                 esi, dword ptr [eax + 2]
            //   8da42400000000       | lea                 esp, dword ptr [esp]
            //   668b08               | mov                 cx, word ptr [eax]
            //   83c002               | add                 eax, 2

        $sequence_33 = { 83c002 6685c9 75f5 2bc2 b9???????? d1f8 8d7102 }
            // n = 7, score = 300
            //   83c002               | add                 eax, 2
            //   6685c9               | test                cx, cx
            //   75f5                 | jne                 0xfffffff7
            //   2bc2                 | sub                 eax, edx
            //   b9????????           |                     
            //   d1f8                 | sar                 eax, 1
            //   8d7102               | lea                 esi, dword ptr [ecx + 2]

        $sequence_34 = { 50 ff15???????? 0fb74c2416 0fb7542414 }
            // n = 4, score = 300
            //   50                   | push                eax
            //   ff15????????         |                     
            //   0fb74c2416           | movzx               ecx, word ptr [esp + 0x16]
            //   0fb7542414           | movzx               edx, word ptr [esp + 0x14]

        $sequence_35 = { 6685c9 75f5 2bc6 03d2 }
            // n = 4, score = 300
            //   6685c9               | test                cx, cx
            //   75f5                 | jne                 0xfffffff7
            //   2bc6                 | sub                 eax, esi
            //   03d2                 | add                 edx, edx

        $sequence_36 = { 68???????? 33ff 57 57 ff15???????? 8bf0 }
            // n = 6, score = 300
            //   68????????           |                     
            //   33ff                 | xor                 edi, edi
            //   57                   | push                edi
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_37 = { e8???????? 83c40c 68???????? ffd6 50 68???????? 57 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   50                   | push                eax
            //   68????????           |                     
            //   57                   | push                edi

        $sequence_38 = { 68???????? 57 ffd6 03c7 50 }
            // n = 5, score = 300
            //   68????????           |                     
            //   57                   | push                edi
            //   ffd6                 | call                esi
            //   03c7                 | add                 eax, edi
            //   50                   | push                eax

        $sequence_39 = { 83c40c eb0d 6a00 6800020000 ff15???????? }
            // n = 5, score = 300
            //   83c40c               | add                 esp, 0xc
            //   eb0d                 | jmp                 0xf
            //   6a00                 | push                0
            //   6800020000           | push                0x200
            //   ff15????????         |                     

        $sequence_40 = { 75f5 8d1400 2bce 52 }
            // n = 4, score = 300
            //   75f5                 | jne                 0xfffffff7
            //   8d1400               | lea                 edx, dword ptr [eax + eax]
            //   2bce                 | sub                 ecx, esi
            //   52                   | push                edx

        $sequence_41 = { 8d4580 50 ff15???????? 0fb7458c 50 }
            // n = 5, score = 100
            //   8d4580               | lea                 eax, dword ptr [ebp - 0x80]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   0fb7458c             | movzx               eax, word ptr [ebp - 0x74]
            //   50                   | push                eax

        $sequence_42 = { 897558 eb07 c7455801000000 39756c 74c5 }
            // n = 5, score = 100
            //   897558               | mov                 dword ptr [ebp + 0x58], esi
            //   eb07                 | jmp                 9
            //   c7455801000000       | mov                 dword ptr [ebp + 0x58], 1
            //   39756c               | cmp                 dword ptr [ebp + 0x6c], esi
            //   74c5                 | je                  0xffffffc7

        $sequence_43 = { 84c0 7524 8b4514 8945f8 }
            // n = 4, score = 100
            //   84c0                 | test                al, al
            //   7524                 | jne                 0x26
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   8945f8               | mov                 dword ptr [ebp - 8], eax

        $sequence_44 = { 83c048 50 e8???????? 59 59 85c0 741f }
            // n = 7, score = 100
            //   83c048               | add                 eax, 0x48
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   741f                 | je                  0x21

        $sequence_45 = { 83e11f 8bf0 c1fe05 c1e106 030cb520100210 eb02 }
            // n = 6, score = 100
            //   83e11f               | and                 ecx, 0x1f
            //   8bf0                 | mov                 esi, eax
            //   c1fe05               | sar                 esi, 5
            //   c1e106               | shl                 ecx, 6
            //   030cb520100210       | add                 ecx, dword ptr [esi*4 + 0x10021020]
            //   eb02                 | jmp                 4

    condition:
        7 of them and filesize < 401408
}