rule win_bazarbackdoor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.bazarbackdoor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bazarbackdoor"
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
        $sequence_0 = { 0fb6c8 e8???????? 85c0 7403 }
            // n = 4, score = 1800
            //   0fb6c8               | movzx               ecx, al
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7403                 | je                  5

        $sequence_1 = { 4032ff 8a03 3c20 7709 }
            // n = 4, score = 1600
            //   4032ff               | dec                 eax
            //   8a03                 | inc                 ebx
            //   3c20                 | jmp                 0xffffffd4
            //   7709                 | cmp                 al, 0x20

        $sequence_2 = { 7709 84c0 7431 4084ff 741f }
            // n = 5, score = 1600
            //   7709                 | inc                 ebx
            //   84c0                 | jmp                 0xffffffd7
            //   7431                 | cmp                 al, 0x20
            //   4084ff               | ja                  0x12
            //   741f                 | dec                 eax

        $sequence_3 = { 3c22 7507 4084ff 400f94c7 0fb6c8 e8???????? }
            // n = 6, score = 1600
            //   3c22                 | dec                 eax
            //   7507                 | cmovne              ebx, eax
            //   4084ff               | inc                 eax
            //   400f94c7             | xor                 bh, bh
            //   0fb6c8               | mov                 al, byte ptr [ebx]
            //   e8????????           |                     

        $sequence_4 = { 7403 48ffc3 48ffc3 ebd2 3c20 7709 }
            // n = 6, score = 1600
            //   7403                 | test                bh, bh
            //   48ffc3               | inc                 eax
            //   48ffc3               | sete                bh
            //   ebd2                 | movzx               ecx, al
            //   3c20                 | dec                 eax
            //   7709                 | test                eax, eax

        $sequence_5 = { ebd2 3c20 7709 48ffc3 8a03 84c0 }
            // n = 6, score = 1600
            //   ebd2                 | jmp                 0xffffffd4
            //   3c20                 | cmp                 al, 0x20
            //   7709                 | ja                  0xb
            //   48ffc3               | dec                 eax
            //   8a03                 | inc                 ebx
            //   84c0                 | inc                 eax

        $sequence_6 = { 41b80f100000 488bce 4889442420 ff15???????? }
            // n = 4, score = 1500
            //   41b80f100000         | jmp                 0xffffffda
            //   488bce               | cmp                 al, 0x20
            //   4889442420           | ja                  0x15
            //   ff15????????         |                     

        $sequence_7 = { ff15???????? 85c0 780a 4898 }
            // n = 4, score = 1500
            //   ff15????????         |                     
            //   85c0                 | inc                 ebx
            //   780a                 | dec                 eax
            //   4898                 | inc                 ebx

        $sequence_8 = { b902000000 e8???????? e8???????? 8bc8 e8???????? e8???????? 8bd8 }
            // n = 7, score = 1400
            //   b902000000           | push                ebp
            //   e8????????           |                     
            //   e8????????           |                     
            //   8bc8                 | push                ebx
            //   e8????????           |                     
            //   e8????????           |                     
            //   8bd8                 | dec                 eax

        $sequence_9 = { b92c010000 ffd0 ffc3 83fb06 }
            // n = 4, score = 1300
            //   b92c010000           | inc                 eax
            //   ffd0                 | test                bh, bh
            //   ffc3                 | inc                 eax
            //   83fb06               | sete                bh

        $sequence_10 = { 41b841587c4c e8???????? 4885c0 740a ba02000000 }
            // n = 5, score = 1300
            //   41b841587c4c         | inc                 ebx
            //   e8????????           |                     
            //   4885c0               | jmp                 0xffffffd7
            //   740a                 | cmp                 al, 0x20
            //   ba02000000           | ja                  0xd

        $sequence_11 = { 41b8e6b5a12c 448d4a7d e8???????? 4885c0 740c }
            // n = 5, score = 1300
            //   41b8e6b5a12c         | je                  0x24
            //   448d4a7d             | cmp                 al, 0x22
            //   e8????????           |                     
            //   4885c0               | jne                 0x10
            //   740c                 | dec                 eax

        $sequence_12 = { 72b1 8b4728 33f6 488b5568 }
            // n = 4, score = 1300
            //   72b1                 | cmp                 al, 0x22
            //   8b4728               | jne                 0xd
            //   33f6                 | cmp                 al, 0x22
            //   488b5568             | jne                 0xb

        $sequence_13 = { 488bcf ffd0 b803000000 e9???????? }
            // n = 4, score = 1300
            //   488bcf               | inc                 eax
            //   ffd0                 | sete                bh
            //   b803000000           | movzx               ecx, al
            //   e9????????           |                     

        $sequence_14 = { 0fb74f02 0fb7d8 ff15???????? 0fb74f08 }
            // n = 4, score = 1100
            //   0fb74f02             | jmp                 0xffffffda
            //   0fb7d8               | cmp                 al, 0x20
            //   ff15????????         |                     
            //   0fb74f08             | ja                  0x15

        $sequence_15 = { 0fb70f ff15???????? 0fb74f02 0fb7d8 }
            // n = 4, score = 1100
            //   0fb70f               | je                  0x33
            //   ff15????????         |                     
            //   0fb74f02             | inc                 eax
            //   0fb7d8               | test                bh, bh

        $sequence_16 = { 7507 33c0 e9???????? b8ff000000 }
            // n = 4, score = 1000
            //   7507                 | jne                 9
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   b8ff000000           | mov                 eax, 0xff

        $sequence_17 = { c3 0fb74c0818 b80b010000 663bc8 }
            // n = 4, score = 900
            //   c3                   | inc                 ebx
            //   0fb74c0818           | test                al, al
            //   b80b010000           | je                  0x33
            //   663bc8               | inc                 eax

        $sequence_18 = { e8???????? 4c89e1 e8???????? 8b05???????? }
            // n = 4, score = 800
            //   e8????????           |                     
            //   4c89e1               | dec                 eax
            //   e8????????           |                     
            //   8b05????????         |                     

        $sequence_19 = { e8???????? 4889c7 8b05???????? 8b0d???????? }
            // n = 4, score = 800
            //   e8????????           |                     
            //   4889c7               | dec                 eax
            //   8b05????????         |                     
            //   8b0d????????         |                     

        $sequence_20 = { ff15???????? 4889c1 31d2 4d89e0 }
            // n = 4, score = 800
            //   ff15????????         |                     
            //   4889c1               | jbe                 0x1d
            //   31d2                 | dec                 eax
            //   4d89e0               | mov                 eax, dword ptr [esp + 8]

        $sequence_21 = { 4889f1 e8???????? 8b05???????? 8b0d???????? }
            // n = 4, score = 800
            //   4889f1               | js                  0xe
            //   e8????????           |                     
            //   8b05????????         |                     
            //   8b0d????????         |                     

        $sequence_22 = { 31ff 4889c1 31d2 4989f0 }
            // n = 4, score = 800
            //   31ff                 | dec                 eax
            //   4889c1               | mov                 eax, dword ptr [esp + 0x70]
            //   31d2                 | dec                 eax
            //   4989f0               | cmp                 dword ptr [esp + 0x78], eax

        $sequence_23 = { 4889f0 4883c438 5b 5d 5f }
            // n = 5, score = 700
            //   4889f0               | dec                 eax
            //   4883c438             | mov                 dword ptr [esp + 0x20], eax
            //   5b                   | test                eax, eax
            //   5d                   | js                  0xe
            //   5f                   | dec                 eax

        $sequence_24 = { c644246800 8b05???????? 8d48ff 0fafc8 }
            // n = 4, score = 700
            //   c644246800           | inc                 eax
            //   8b05????????         |                     
            //   8d48ff               | test                bh, bh
            //   0fafc8               | je                  0x21

        $sequence_25 = { e9???????? 8b05???????? 8b15???????? 8d48ff 0fafc8 89c8 }
            // n = 6, score = 700
            //   e9????????           |                     
            //   8b05????????         |                     
            //   8b15????????         |                     
            //   8d48ff               | ja                  0xf
            //   0fafc8               | test                al, al
            //   89c8                 | dec                 eax

        $sequence_26 = { ff15???????? 31ed 4889c1 31d2 }
            // n = 4, score = 700
            //   ff15????????         |                     
            //   31ed                 | mov                 eax, dword ptr [eax + 8]
            //   4889c1               | dec                 eax
            //   31d2                 | mov                 dword ptr [esp + 0x38], eax

        $sequence_27 = { e8???????? 8b0d???????? 8d51ff 0fafd1 89d1 }
            // n = 5, score = 700
            //   e8????????           |                     
            //   8b0d????????         |                     
            //   8d51ff               | cmp                 al, 0x20
            //   0fafd1               | ja                  0x12
            //   89d1                 | test                al, al

        $sequence_28 = { c744242880000000 c744242003000000 4889f9 ba00000080 41b801000000 4531c9 }
            // n = 6, score = 700
            //   c744242880000000     | lea                 ecx, dword ptr [edx + 0x7d]
            //   c744242003000000     | dec                 eax
            //   4889f9               | test                eax, eax
            //   ba00000080           | jne                 0xc
            //   41b801000000         | mov                 eax, 0x31
            //   4531c9               | inc                 ecx

        $sequence_29 = { 0fb64b04 0fb6d1 80f973 7504 }
            // n = 4, score = 700
            //   0fb64b04             | cmp                 al, 0x20
            //   0fb6d1               | ja                  0xd
            //   80f973               | test                al, al
            //   7504                 | je                  0x39

        $sequence_30 = { 8bd3 e8???????? 33c0 e9???????? }
            // n = 4, score = 700
            //   8bd3                 | inc                 eax
            //   e8????????           |                     
            //   33c0                 | test                bh, bh
            //   e9????????           |                     

        $sequence_31 = { c3 8b05???????? 8d50ff 0fafd0 89d0 }
            // n = 5, score = 700
            //   c3                   | je                  5
            //   8b05????????         |                     
            //   8d50ff               | dec                 eax
            //   0fafd0               | inc                 ebx
            //   89d0                 | movzx               ecx, al

        $sequence_32 = { e8???????? 4889f9 4889f2 ffd0 }
            // n = 4, score = 700
            //   e8????????           |                     
            //   4889f9               | inc                 ecx
            //   4889f2               | mov                 eax, 0x2ca1b5e6
            //   ffd0                 | inc                 esp

        $sequence_33 = { 57 55 53 4881ec78010000 }
            // n = 4, score = 700
            //   57                   | xor                 ecx, ecx
            //   55                   | inc                 ecx
            //   53                   | mov                 eax, 0x2ca1b5e6
            //   4881ec78010000       | inc                 esp

        $sequence_34 = { e9???????? 8b05???????? 8b0d???????? 8d50ff }
            // n = 4, score = 700
            //   e9????????           |                     
            //   8b05????????         |                     
            //   8b0d????????         |                     
            //   8d50ff               | je                  0x3e

        $sequence_35 = { 4889c1 31d2 4989f8 ff15???????? 4885c0 }
            // n = 5, score = 700
            //   4889c1               | add                 ecx, eax
            //   31d2                 | dec                 eax
            //   4989f8               | mov                 eax, ecx
            //   ff15????????         |                     
            //   4885c0               | dec                 eax

        $sequence_36 = { 57 53 4883ec20 4889d7 }
            // n = 4, score = 700
            //   57                   | mov                 ecx, esi
            //   53                   | dec                 eax
            //   4883ec20             | mov                 dword ptr [esp + 0x20], eax
            //   4889d7               | test                eax, eax

        $sequence_37 = { e8???????? b902000000 31d2 ffd0 }
            // n = 4, score = 700
            //   e8????????           |                     
            //   b902000000           | inc                 eax
            //   31d2                 | test                bh, bh
            //   ffd0                 | je                  0x21

        $sequence_38 = { 80f973 7504 0fb65305 33c0 }
            // n = 4, score = 700
            //   80f973               | jne                 9
            //   7504                 | inc                 eax
            //   0fb65305             | test                bh, bh
            //   33c0                 | inc                 eax

        $sequence_39 = { 84d2 7405 80fa2e 750f }
            // n = 4, score = 600
            //   84d2                 | inc                 eax
            //   7405                 | sete                bh
            //   80fa2e               | movzx               ecx, al
            //   750f                 | mov                 al, byte ptr [ebx]

        $sequence_40 = { e8???????? 4c897c2420 4889d9 89fa }
            // n = 4, score = 600
            //   e8????????           |                     
            //   4c897c2420           | dec                 eax
            //   4889d9               | mov                 edx, dword ptr [esp + 0x88]
            //   89fa                 | dec                 eax

        $sequence_41 = { 4889c1 31d2 4d89f8 ffd3 }
            // n = 4, score = 600
            //   4889c1               | cwde                
            //   31d2                 | inc                 ecx
            //   4d89f8               | mov                 eax, 0x100f
            //   ffd3                 | dec                 eax

        $sequence_42 = { 4889da e8???????? 4889f1 4889da e8???????? }
            // n = 5, score = 600
            //   4889da               | mov                 dword ptr [esp + 0x20], eax
            //   e8????????           |                     
            //   4889f1               | test                eax, eax
            //   4889da               | js                  0xe
            //   e8????????           |                     

        $sequence_43 = { e8???????? 59 3b442414 741e 8b442410 83c504 83c302 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   3b442414             | cmp                 eax, dword ptr [esp + 0x14]
            //   741e                 | je                  0x20
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   83c504               | add                 ebp, 4
            //   83c302               | add                 ebx, 2

        $sequence_44 = { 88443c10 47 42 84db 7502 ff06 }
            // n = 6, score = 400
            //   88443c10             | mov                 byte ptr [esp + edi + 0x10], al
            //   47                   | inc                 edi
            //   42                   | inc                 edx
            //   84db                 | test                bl, bl
            //   7502                 | jne                 4
            //   ff06                 | inc                 dword ptr [esi]

        $sequence_45 = { a3???????? 85c0 7507 6a37 e9???????? }
            // n = 5, score = 400
            //   a3????????           |                     
            //   85c0                 | test                eax, eax
            //   7507                 | jne                 9
            //   6a37                 | push                0x37
            //   e9????????           |                     

        $sequence_46 = { 740b 396c846c 7405 40 3bc6 72f5 }
            // n = 6, score = 400
            //   740b                 | je                  0xd
            //   396c846c             | cmp                 dword ptr [esp + eax*4 + 0x6c], ebp
            //   7405                 | je                  7
            //   40                   | inc                 eax
            //   3bc6                 | cmp                 eax, esi
            //   72f5                 | jb                  0xfffffff7

        $sequence_47 = { 8be5 5d c3 56 8bf1 8d4e7c e8???????? }
            // n = 7, score = 400
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   8d4e7c               | lea                 ecx, dword ptr [esi + 0x7c]
            //   e8????????           |                     

        $sequence_48 = { 0fb745e8 50 68???????? e8???????? }
            // n = 4, score = 400
            //   0fb745e8             | movzx               eax, word ptr [ebp - 0x18]
            //   50                   | push                eax
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_49 = { 83c41c c3 56 8bf2 33d2 6a09 }
            // n = 6, score = 400
            //   83c41c               | add                 esp, 0x1c
            //   c3                   | ret                 
            //   56                   | push                esi
            //   8bf2                 | mov                 esi, edx
            //   33d2                 | xor                 edx, edx
            //   6a09                 | push                9

        $sequence_50 = { c1f910 0fb6c1 50 8bc2 c1f808 0fb6c0 }
            // n = 6, score = 300
            //   c1f910               | sar                 ecx, 0x10
            //   0fb6c1               | movzx               eax, cl
            //   50                   | push                eax
            //   8bc2                 | mov                 eax, edx
            //   c1f808               | sar                 eax, 8
            //   0fb6c0               | movzx               eax, al

        $sequence_51 = { ff7508 56 ff15???????? 6a00 }
            // n = 4, score = 300
            //   ff7508               | push                dword ptr [ebp + 8]
            //   56                   | push                esi
            //   ff15????????         |                     
            //   6a00                 | push                0

        $sequence_52 = { 6a04 68???????? ff15???????? 8bf8 83ffff 7424 }
            // n = 6, score = 300
            //   6a04                 | push                4
            //   68????????           |                     
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   83ffff               | cmp                 edi, -1
            //   7424                 | je                  0x26

        $sequence_53 = { 0fb6c9 51 8bca c1f910 }
            // n = 4, score = 300
            //   0fb6c9               | movzx               ecx, cl
            //   51                   | push                ecx
            //   8bca                 | mov                 ecx, edx
            //   c1f910               | sar                 ecx, 0x10

        $sequence_54 = { ff15???????? 8bf0 8d7e02 57 6a08 ff15???????? 50 }
            // n = 7, score = 300
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   8d7e02               | lea                 edi, dword ptr [esi + 2]
            //   57                   | push                edi
            //   6a08                 | push                8
            //   ff15????????         |                     
            //   50                   | push                eax

        $sequence_55 = { 53 8b1d???????? ffd3 8b3d???????? 8d7001 8d4610 50 }
            // n = 7, score = 300
            //   53                   | push                ebx
            //   8b1d????????         |                     
            //   ffd3                 | call                ebx
            //   8b3d????????         |                     
            //   8d7001               | lea                 esi, dword ptr [eax + 1]
            //   8d4610               | lea                 eax, dword ptr [esi + 0x10]
            //   50                   | push                eax

        $sequence_56 = { 8ac1 2ac2 fec8 88041a 8bd1 }
            // n = 5, score = 300
            //   8ac1                 | mov                 al, cl
            //   2ac2                 | sub                 al, dl
            //   fec8                 | dec                 al
            //   88041a               | mov                 byte ptr [edx + ebx], al
            //   8bd1                 | mov                 edx, ecx

        $sequence_57 = { 50 8bd9 53 6a02 ff15???????? }
            // n = 5, score = 300
            //   50                   | push                eax
            //   8bd9                 | mov                 ebx, ecx
            //   53                   | push                ebx
            //   6a02                 | push                2
            //   ff15????????         |                     

        $sequence_58 = { ffc0 488b8c2488000000 894118 488b442428 833800 7431 488b442428 }
            // n = 7, score = 100
            //   ffc0                 | cmp                 al, 0x22
            //   488b8c2488000000     | jne                 0xb
            //   894118               | inc                 eax
            //   488b442428           | test                bh, bh
            //   833800               | je                  0x21
            //   7431                 | cmp                 al, 0x22
            //   488b442428           | jne                 0xb

        $sequence_59 = { 488b442408 0fb600 488b4c2410 0fb609 3bc1 751c 488b442408 }
            // n = 7, score = 100
            //   488b442408           | je                  7
            //   0fb600               | dec                 eax
            //   488b4c2410           | inc                 ebx
            //   0fb609               | dec                 eax
            //   3bc1                 | inc                 ebx
            //   751c                 | jmp                 0xffffffde
            //   488b442408           | inc                 eax

        $sequence_60 = { 448bc0 488bd1 488b4c2430 e8???????? 488b442428 8b4c2430 }
            // n = 6, score = 100
            //   448bc0               | test                bh, bh
            //   488bd1               | inc                 eax
            //   488b4c2430           | sete                bh
            //   e8????????           |                     
            //   488b442428           | movzx               ecx, al
            //   8b4c2430             | je                  0x21

        $sequence_61 = { 034110 8bc0 4889442478 488b442470 4839442478 760a }
            // n = 6, score = 100
            //   034110               | sete                bh
            //   8bc0                 | movzx               ecx, al
            //   4889442478           | test                eax, eax
            //   488b442470           | je                  0x11
            //   4839442478           | movzx               ecx, al
            //   760a                 | test                eax, eax

        $sequence_62 = { 488b542430 488b8c24f0000000 e8???????? 488b4c2430 894124 }
            // n = 5, score = 100
            //   488b542430           | jne                 9
            //   488b8c24f0000000     | inc                 eax
            //   e8????????           |                     
            //   488b4c2430           | test                bh, bh
            //   894124               | inc                 eax

        $sequence_63 = { 0fbaf019 8944245c eb14 488b442428 8b4024 8b4c245c }
            // n = 6, score = 100
            //   0fbaf019             | inc                 eax
            //   8944245c             | test                bh, bh
            //   eb14                 | je                  0x21
            //   488b442428           | cmp                 al, 0x22
            //   8b4024               | jne                 0xb
            //   8b4c245c             | inc                 eax

        $sequence_64 = { e9???????? 488b442430 8b4020 488b4c2438 4803c8 488bc1 4889442440 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   488b442430           | inc                 ebx
            //   8b4020               | inc                 eax
            //   488b4c2438           | test                bh, bh
            //   4803c8               | inc                 eax
            //   488bc1               | sete                bh
            //   4889442440           | movzx               ecx, al

        $sequence_65 = { 4889542410 48894c2408 4883ec48 488b442470 488b4008 4889442438 488b442470 }
            // n = 7, score = 100
            //   4889542410           | test                bh, bh
            //   48894c2408           | inc                 eax
            //   4883ec48             | sete                bh
            //   488b442470           | movzx               ecx, al
            //   488b4008             | test                eax, eax
            //   4889442438           | je                  0xe
            //   488b442470           | dec                 eax

    condition:
        7 of them and filesize < 2088960
}