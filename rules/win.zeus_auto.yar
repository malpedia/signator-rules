rule win_zeus_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.zeus."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zeus"
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
        $sequence_0 = { eb58 833f00 7651 8b5f08 }
            // n = 4, score = 700
            //   eb58                 | jmp                 0x5a
            //   833f00               | cmp                 dword ptr [edi], 0
            //   7651                 | jbe                 0x53
            //   8b5f08               | mov                 ebx, dword ptr [edi + 8]

        $sequence_1 = { c9 c20c00 55 8bec 81ec34040000 53 56 }
            // n = 7, score = 600
            //   c9                   | leave               
            //   c20c00               | ret                 0xc
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec34040000         | sub                 esp, 0x434
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_2 = { e8???????? fe45fb 807dfb03 8975e4 c6043000 0f8283fdffff }
            // n = 6, score = 600
            //   e8????????           |                     
            //   fe45fb               | inc                 byte ptr [ebp - 5]
            //   807dfb03             | cmp                 byte ptr [ebp - 5], 3
            //   8975e4               | mov                 dword ptr [ebp - 0x1c], esi
            //   c6043000             | mov                 byte ptr [eax + esi], 0
            //   0f8283fdffff         | jb                  0xfffffd89

        $sequence_3 = { 8d442428 50 0fb64304 50 }
            // n = 4, score = 600
            //   8d442428             | lea                 eax, [esp + 0x28]
            //   50                   | push                eax
            //   0fb64304             | movzx               eax, byte ptr [ebx + 4]
            //   50                   | push                eax

        $sequence_4 = { eb03 8b4df8 8a01 894df4 eb0c 3c3b 740c }
            // n = 7, score = 600
            //   eb03                 | jmp                 5
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   8a01                 | mov                 al, byte ptr [ecx]
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   eb0c                 | jmp                 0xe
            //   3c3b                 | cmp                 al, 0x3b
            //   740c                 | je                  0xe

        $sequence_5 = { 80f923 750b 3b7dfc 0f8440010000 eb25 }
            // n = 5, score = 600
            //   80f923               | cmp                 cl, 0x23
            //   750b                 | jne                 0xd
            //   3b7dfc               | cmp                 edi, dword ptr [ebp - 4]
            //   0f8440010000         | je                  0x146
            //   eb25                 | jmp                 0x27

        $sequence_6 = { 8b55f8 8b5df0 88040a eb4e 837df400 }
            // n = 5, score = 600
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   8b5df0               | mov                 ebx, dword ptr [ebp - 0x10]
            //   88040a               | mov                 byte ptr [edx + ecx], al
            //   eb4e                 | jmp                 0x50
            //   837df400             | cmp                 dword ptr [ebp - 0xc], 0

        $sequence_7 = { 8b16 8b02 03c2 897808 85ff 760d 57 }
            // n = 7, score = 600
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   03c2                 | add                 eax, edx
            //   897808               | mov                 dword ptr [eax + 8], edi
            //   85ff                 | test                edi, edi
            //   760d                 | jbe                 0xf
            //   57                   | push                edi

        $sequence_8 = { e8???????? 84c0 7442 6a10 }
            // n = 4, score = 500
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7442                 | je                  0x44
            //   6a10                 | push                0x10

        $sequence_9 = { 8bf3 6810270000 ff35???????? ff15???????? }
            // n = 4, score = 500
            //   8bf3                 | mov                 esi, ebx
            //   6810270000           | push                0x2710
            //   ff35????????         |                     
            //   ff15????????         |                     

        $sequence_10 = { 891d???????? 891d???????? ffd6 68???????? }
            // n = 4, score = 500
            //   891d????????         |                     
            //   891d????????         |                     
            //   ffd6                 | call                esi
            //   68????????           |                     

        $sequence_11 = { 8d8db0fdffff e8???????? 8ad8 84db }
            // n = 4, score = 400
            //   8d8db0fdffff         | lea                 ecx, [ebp - 0x250]
            //   e8????????           |                     
            //   8ad8                 | mov                 bl, al
            //   84db                 | test                bl, bl

        $sequence_12 = { c20400 55 8bec f6451802 }
            // n = 4, score = 300
            //   c20400               | ret                 4
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   f6451802             | test                byte ptr [ebp + 0x18], 2

        $sequence_13 = { 5e 8ac3 5b c20800 55 8bec 83e4f8 }
            // n = 7, score = 300
            //   5e                   | pop                 esi
            //   8ac3                 | mov                 al, bl
            //   5b                   | pop                 ebx
            //   c20800               | ret                 8
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83e4f8               | and                 esp, 0xfffffff8

        $sequence_14 = { 8b03 3509080002 3d5c5b4550 740b }
            // n = 4, score = 200
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   3509080002           | xor                 eax, 0x2000809
            //   3d5c5b4550           | cmp                 eax, 0x50455b5c
            //   740b                 | je                  0xd

        $sequence_15 = { ff35???????? e8???????? 5f 5e 8ac3 }
            // n = 5, score = 200
            //   ff35????????         |                     
            //   e8????????           |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8ac3                 | mov                 al, bl

        $sequence_16 = { 0f84ac000000 b809080002 3945f4 7713 }
            // n = 4, score = 200
            //   0f84ac000000         | je                  0xb2
            //   b809080002           | mov                 eax, 0x2000809
            //   3945f4               | cmp                 dword ptr [ebp - 0xc], eax
            //   7713                 | ja                  0x15

        $sequence_17 = { 81fb5a5c4156 740c 81fb45415356 0f85b2000000 }
            // n = 4, score = 200
            //   81fb5a5c4156         | cmp                 ebx, 0x56415c5a
            //   740c                 | je                  0xe
            //   81fb45415356         | cmp                 ebx, 0x56534145
            //   0f85b2000000         | jne                 0xb8

        $sequence_18 = { b001 5b 8be5 5d c3 66833d????????00 56 }
            // n = 7, score = 200
            //   b001                 | mov                 al, 1
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   66833d????????00     |                     
            //   56                   | push                esi

        $sequence_19 = { 5b 8bc6 c745f809080002 e8???????? 8ad8 f6450c04 }
            // n = 6, score = 200
            //   5b                   | pop                 ebx
            //   8bc6                 | mov                 eax, esi
            //   c745f809080002       | mov                 dword ptr [ebp - 8], 0x2000809
            //   e8????????           |                     
            //   8ad8                 | mov                 bl, al
            //   f6450c04             | test                byte ptr [ebp + 0xc], 4

        $sequence_20 = { 68e6010000 68???????? 6809080002 8bc6 50 8d45fc }
            // n = 6, score = 200
            //   68e6010000           | push                0x1e6
            //   68????????           |                     
            //   6809080002           | push                0x2000809
            //   8bc6                 | mov                 eax, esi
            //   50                   | push                eax
            //   8d45fc               | lea                 eax, [ebp - 4]

        $sequence_21 = { 894736 8d470c 50 c707000e0000 c7470809080002 }
            // n = 5, score = 200
            //   894736               | mov                 dword ptr [edi + 0x36], eax
            //   8d470c               | lea                 eax, [edi + 0xc]
            //   50                   | push                eax
            //   c707000e0000         | mov                 dword ptr [edi], 0xe00
            //   c7470809080002       | mov                 dword ptr [edi + 8], 0x2000809

        $sequence_22 = { b9???????? 56 57 33f6 56 }
            // n = 5, score = 200
            //   b9????????           |                     
            //   56                   | push                esi
            //   57                   | push                edi
            //   33f6                 | xor                 esi, esi
            //   56                   | push                esi

        $sequence_23 = { 7506 807b0244 7429 83fe04 0f82ec000000 8b1b 81f309080002 }
            // n = 7, score = 200
            //   7506                 | jne                 8
            //   807b0244             | cmp                 byte ptr [ebx + 2], 0x44
            //   7429                 | je                  0x2b
            //   83fe04               | cmp                 esi, 4
            //   0f82ec000000         | jb                  0xf2
            //   8b1b                 | mov                 ebx, dword ptr [ebx]
            //   81f309080002         | xor                 ebx, 0x2000809

    condition:
        7 of them and filesize < 319488
}