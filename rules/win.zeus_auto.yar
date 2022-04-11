rule win_zeus_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.zeus."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zeus"
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
        $sequence_0 = { eb58 833f00 7651 8b5f08 }
            // n = 4, score = 700
            //   eb58                 | jmp                 0x5a
            //   833f00               | cmp                 dword ptr [edi], 0
            //   7651                 | jbe                 0x53
            //   8b5f08               | mov                 ebx, dword ptr [edi + 8]

        $sequence_1 = { 807c06010a 750b 80fb0a 7506 }
            // n = 4, score = 600
            //   807c06010a           | cmp                 byte ptr [esi + eax + 1], 0xa
            //   750b                 | jne                 0xd
            //   80fb0a               | cmp                 bl, 0xa
            //   7506                 | jne                 8

        $sequence_2 = { 807c16ff2f 7411 8b4d0c 8b55fc }
            // n = 4, score = 600
            //   807c16ff2f           | cmp                 byte ptr [esi + edx - 1], 0x2f
            //   7411                 | je                  0x13
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]

        $sequence_3 = { 807c241302 7506 8b442418 eb10 }
            // n = 4, score = 600
            //   807c241302           | cmp                 byte ptr [esp + 0x13], 2
            //   7506                 | jne                 8
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]
            //   eb10                 | jmp                 0x12

        $sequence_4 = { 807d0c01 8b4510 8b5518 8930 }
            // n = 4, score = 600
            //   807d0c01             | cmp                 byte ptr [ebp + 0xc], 1
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8b5518               | mov                 edx, dword ptr [ebp + 0x18]
            //   8930                 | mov                 dword ptr [eax], esi

        $sequence_5 = { 807c241300 8b442414 7405 b830750000 }
            // n = 4, score = 600
            //   807c241300           | cmp                 byte ptr [esp + 0x13], 0
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   7405                 | je                  7
            //   b830750000           | mov                 eax, 0x7530

        $sequence_6 = { 807c02010a 0f8513ffffff 80f90a 0f850affffff 42 ff45f4 eb0e }
            // n = 7, score = 600
            //   807c02010a           | cmp                 byte ptr [edx + eax + 1], 0xa
            //   0f8513ffffff         | jne                 0xffffff19
            //   80f90a               | cmp                 cl, 0xa
            //   0f850affffff         | jne                 0xffffff10
            //   42                   | inc                 edx
            //   ff45f4               | inc                 dword ptr [ebp - 0xc]
            //   eb0e                 | jmp                 0x10

        $sequence_7 = { 807d1700 740b 8b07 83f8ff }
            // n = 4, score = 600
            //   807d1700             | cmp                 byte ptr [ebp + 0x17], 0
            //   740b                 | je                  0xd
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   83f8ff               | cmp                 eax, -1

        $sequence_8 = { 891d???????? 891d???????? ffd6 68???????? }
            // n = 4, score = 500
            //   891d????????         |                     
            //   891d????????         |                     
            //   ffd6                 | call                esi
            //   68????????           |                     

        $sequence_9 = { 8bf3 6810270000 ff35???????? ff15???????? }
            // n = 4, score = 500
            //   8bf3                 | mov                 esi, ebx
            //   6810270000           | push                0x2710
            //   ff35????????         |                     
            //   ff15????????         |                     

        $sequence_10 = { e8???????? 84c0 7442 6a10 }
            // n = 4, score = 500
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7442                 | je                  0x44
            //   6a10                 | push                0x10

        $sequence_11 = { 8d8db0fdffff e8???????? 8ad8 84db }
            // n = 4, score = 400
            //   8d8db0fdffff         | lea                 ecx, dword ptr [ebp - 0x250]
            //   e8????????           |                     
            //   8ad8                 | mov                 bl, al
            //   84db                 | test                bl, bl

        $sequence_12 = { c20400 55 8bec f6451802 }
            // n = 4, score = 300
            //   c20400               | ret                 4
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   f6451802             | test                byte ptr [ebp + 0x18], 2

        $sequence_13 = { ff15???????? 5e 8ac3 5b c20800 55 8bec }
            // n = 7, score = 300
            //   ff15????????         |                     
            //   5e                   | pop                 esi
            //   8ac3                 | mov                 al, bl
            //   5b                   | pop                 ebx
            //   c20800               | ret                 8
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp

        $sequence_14 = { c707000e0000 c7470809080002 e8???????? 83674200 6a78 }
            // n = 5, score = 200
            //   c707000e0000         | mov                 dword ptr [edi], 0xe00
            //   c7470809080002       | mov                 dword ptr [edi + 8], 0x2000809
            //   e8????????           |                     
            //   83674200             | and                 dword ptr [edi + 0x42], 0
            //   6a78                 | push                0x78

        $sequence_15 = { 7506 b364 6a14 eb18 81fb5a5c4156 }
            // n = 5, score = 200
            //   7506                 | jne                 8
            //   b364                 | mov                 bl, 0x64
            //   6a14                 | push                0x14
            //   eb18                 | jmp                 0x1a
            //   81fb5a5c4156         | cmp                 ebx, 0x56415c5a

        $sequence_16 = { e8???????? 68e6010000 68???????? 6809080002 8bc6 50 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   68e6010000           | push                0x1e6
            //   68????????           |                     
            //   6809080002           | push                0x2000809
            //   8bc6                 | mov                 eax, esi
            //   50                   | push                eax

        $sequence_17 = { 57 33f6 56 50 68???????? }
            // n = 5, score = 200
            //   57                   | push                edi
            //   33f6                 | xor                 esi, esi
            //   56                   | push                esi
            //   50                   | push                eax
            //   68????????           |                     

        $sequence_18 = { 83fe06 0f86e3000000 8b03 3509080002 3d5c5b4550 740b 3d59495351 }
            // n = 7, score = 200
            //   83fe06               | cmp                 esi, 6
            //   0f86e3000000         | jbe                 0xe9
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   3509080002           | xor                 eax, 0x2000809
            //   3d5c5b4550           | cmp                 eax, 0x50455b5c
            //   740b                 | je                  0xd
            //   3d59495351           | cmp                 eax, 0x51534959

        $sequence_19 = { eb18 81fb5a5c4156 740c 81fb45415356 0f85b2000000 b365 6a15 }
            // n = 7, score = 200
            //   eb18                 | jmp                 0x1a
            //   81fb5a5c4156         | cmp                 ebx, 0x56415c5a
            //   740c                 | je                  0xe
            //   81fb45415356         | cmp                 ebx, 0x56534145
            //   0f85b2000000         | jne                 0xb8
            //   b365                 | mov                 bl, 0x65
            //   6a15                 | push                0x15

        $sequence_20 = { 81fb5d515047 7410 81fb4f4d4156 7408 }
            // n = 4, score = 200
            //   81fb5d515047         | cmp                 ebx, 0x4750515d
            //   7410                 | je                  0x12
            //   81fb4f4d4156         | cmp                 ebx, 0x56414d4f
            //   7408                 | je                  0xa

        $sequence_21 = { 84c0 0f84ac000000 b809080002 3945f4 7713 807d0801 0f8598000000 }
            // n = 7, score = 200
            //   84c0                 | test                al, al
            //   0f84ac000000         | je                  0xb2
            //   b809080002           | mov                 eax, 0x2000809
            //   3945f4               | cmp                 dword ptr [ebp - 0xc], eax
            //   7713                 | ja                  0x15
            //   807d0801             | cmp                 byte ptr [ebp + 8], 1
            //   0f8598000000         | jne                 0x9e

        $sequence_22 = { 3d59495351 0f85ca000000 807b0420 0f85c0000000 }
            // n = 4, score = 200
            //   3d59495351           | cmp                 eax, 0x51534959
            //   0f85ca000000         | jne                 0xd0
            //   807b0420             | cmp                 byte ptr [ebx + 4], 0x20
            //   0f85c0000000         | jne                 0xc6

    condition:
        7 of them and filesize < 319488
}