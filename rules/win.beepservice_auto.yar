rule win_beepservice_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.beepservice."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.beepservice"
        malpedia_rule_date = "20211007"
        malpedia_hash = "e5b790e0f888f252d49063a1251ca60ec2832535"
        malpedia_version = "20211008"
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
        $sequence_0 = { 8b0d???????? 68???????? ffd6 8bc8 ff15???????? }
            // n = 5, score = 600
            //   8b0d????????         |                     
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   8bc8                 | mov                 ecx, eax
            //   ff15????????         |                     

        $sequence_1 = { 83f801 7505 e8???????? 68???????? 68???????? }
            // n = 5, score = 500
            //   83f801               | cmp                 eax, 1
            //   7505                 | jne                 7
            //   e8????????           |                     
            //   68????????           |                     
            //   68????????           |                     

        $sequence_2 = { 7512 6888130000 68???????? e8???????? 83c408 }
            // n = 5, score = 500
            //   7512                 | jne                 0x14
            //   6888130000           | push                0x1388
            //   68????????           |                     
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_3 = { 683f000f00 6a00 68???????? ff15???????? }
            // n = 4, score = 500
            //   683f000f00           | push                0xf003f
            //   6a00                 | push                0
            //   68????????           |                     
            //   ff15????????         |                     

        $sequence_4 = { e8???????? 83c408 e9???????? 68???????? e8???????? 83c404 6a00 }
            // n = 7, score = 500
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   e9????????           |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   6a00                 | push                0

        $sequence_5 = { 50 68???????? eb43 56 8d45fc }
            // n = 5, score = 400
            //   50                   | push                eax
            //   68????????           |                     
            //   eb43                 | jmp                 0x45
            //   56                   | push                esi
            //   8d45fc               | lea                 eax, dword ptr [ebp - 4]

        $sequence_6 = { e8???????? 83f820 59 730f ff761c }
            // n = 5, score = 400
            //   e8????????           |                     
            //   83f820               | cmp                 eax, 0x20
            //   59                   | pop                 ecx
            //   730f                 | jae                 0x11
            //   ff761c               | push                dword ptr [esi + 0x1c]

        $sequence_7 = { 56 ff742408 8b35???????? ffd6 50 ff15???????? }
            // n = 6, score = 400
            //   56                   | push                esi
            //   ff742408             | push                dword ptr [esp + 8]
            //   8b35????????         |                     
            //   ffd6                 | call                esi
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_8 = { 59 59 ff7604 e8???????? 83f814 59 }
            // n = 6, score = 400
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   ff7604               | push                dword ptr [esi + 4]
            //   e8????????           |                     
            //   83f814               | cmp                 eax, 0x14
            //   59                   | pop                 ecx

        $sequence_9 = { ff7614 e8???????? 50 ff7614 57 }
            // n = 5, score = 400
            //   ff7614               | push                dword ptr [esi + 0x14]
            //   e8????????           |                     
            //   50                   | push                eax
            //   ff7614               | push                dword ptr [esi + 0x14]
            //   57                   | push                edi

        $sequence_10 = { 7517 57 ff15???????? 68???????? e8???????? }
            // n = 5, score = 400
            //   7517                 | jne                 0x19
            //   57                   | push                edi
            //   ff15????????         |                     
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_11 = { 85c0 5b 7514 ff15???????? 50 68???????? }
            // n = 6, score = 400
            //   85c0                 | test                eax, eax
            //   5b                   | pop                 ebx
            //   7514                 | jne                 0x16
            //   ff15????????         |                     
            //   50                   | push                eax
            //   68????????           |                     

        $sequence_12 = { 83e103 f3a4 8b531c 83c9ff 8bfa 33c0 }
            // n = 6, score = 300
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8b531c               | mov                 edx, dword ptr [ebx + 0x1c]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   8bfa                 | mov                 edi, edx
            //   33c0                 | xor                 eax, eax

        $sequence_13 = { 33c0 f2ae f7d1 49 83f920 7320 }
            // n = 6, score = 300
            //   33c0                 | xor                 eax, eax
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx
            //   83f920               | cmp                 ecx, 0x20
            //   7320                 | jae                 0x22

        $sequence_14 = { 83c404 b801000000 5e 81c404020000 c3 ff15???????? }
            // n = 6, score = 300
            //   83c404               | add                 esp, 4
            //   b801000000           | mov                 eax, 1
            //   5e                   | pop                 esi
            //   81c404020000         | add                 esp, 0x204
            //   c3                   | ret                 
            //   ff15????????         |                     

        $sequence_15 = { 33c0 8b5318 8bfa f2ae }
            // n = 4, score = 300
            //   33c0                 | xor                 eax, eax
            //   8b5318               | mov                 edx, dword ptr [ebx + 0x18]
            //   8bfa                 | mov                 edi, edx
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]

        $sequence_16 = { e8???????? 83c408 68f4010000 ff15???????? 8b8df4fdffff 51 ff15???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   68f4010000           | push                0x1f4
            //   ff15????????         |                     
            //   8b8df4fdffff         | mov                 ecx, dword ptr [ebp - 0x20c]
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_17 = { 50 8b8df4fdffff 51 ff15???????? 8985d4fdffff 83bdd4fdffff00 }
            // n = 6, score = 200
            //   50                   | push                eax
            //   8b8df4fdffff         | mov                 ecx, dword ptr [ebp - 0x20c]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8985d4fdffff         | mov                 dword ptr [ebp - 0x22c], eax
            //   83bdd4fdffff00       | cmp                 dword ptr [ebp - 0x22c], 0

        $sequence_18 = { 52 8b450c 50 68???????? 8b0d???????? }
            // n = 5, score = 200
            //   52                   | push                edx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   68????????           |                     
            //   8b0d????????         |                     

        $sequence_19 = { c3 55 8bec 81ec2c020000 c785f4fdffff00000000 c785fcfdffff00000000 683f000f00 }
            // n = 7, score = 200
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec2c020000         | sub                 esp, 0x22c
            //   c785f4fdffff00000000     | mov    dword ptr [ebp - 0x20c], 0
            //   c785fcfdffff00000000     | mov    dword ptr [ebp - 0x204], 0
            //   683f000f00           | push                0xf003f

        $sequence_20 = { 8d44240c 50 53 c744241428010000 e8???????? }
            // n = 5, score = 100
            //   8d44240c             | lea                 eax, dword ptr [esp + 0xc]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   c744241428010000     | mov                 dword ptr [esp + 0x14], 0x128
            //   e8????????           |                     

        $sequence_21 = { a3???????? 33c0 85c9 668935???????? 7e15 b299 }
            // n = 6, score = 100
            //   a3????????           |                     
            //   33c0                 | xor                 eax, eax
            //   85c9                 | test                ecx, ecx
            //   668935????????       |                     
            //   7e15                 | jle                 0x17
            //   b299                 | mov                 dl, 0x99

        $sequence_22 = { 3c39 7f04 3c30 7d02 32db }
            // n = 5, score = 100
            //   3c39                 | cmp                 al, 0x39
            //   7f04                 | jg                  6
            //   3c30                 | cmp                 al, 0x30
            //   7d02                 | jge                 4
            //   32db                 | xor                 bl, bl

        $sequence_23 = { 57 ff15???????? 8945e4 85c0 7407 c745d801000000 }
            // n = 6, score = 100
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   c745d801000000       | mov                 dword ptr [ebp - 0x28], 1

        $sequence_24 = { 8d4c2400 89442400 33c0 51 }
            // n = 4, score = 100
            //   8d4c2400             | lea                 ecx, dword ptr [esp]
            //   89442400             | mov                 dword ptr [esp], eax
            //   33c0                 | xor                 eax, eax
            //   51                   | push                ecx

        $sequence_25 = { 85c0 746b a1???????? 85c0 7562 68e8030000 }
            // n = 6, score = 100
            //   85c0                 | test                eax, eax
            //   746b                 | je                  0x6d
            //   a1????????           |                     
            //   85c0                 | test                eax, eax
            //   7562                 | jne                 0x64
            //   68e8030000           | push                0x3e8

        $sequence_26 = { ff15???????? 8b0d???????? 3599999999 a3???????? 33c0 85c9 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   8b0d????????         |                     
            //   3599999999           | xor                 eax, 0x99999999
            //   a3????????           |                     
            //   33c0                 | xor                 eax, eax
            //   85c9                 | test                ecx, ecx

        $sequence_27 = { 6a40 6800100000 8b5d10 53 56 }
            // n = 5, score = 100
            //   6a40                 | push                0x40
            //   6800100000           | push                0x1000
            //   8b5d10               | mov                 ebx, dword ptr [ebp + 0x10]
            //   53                   | push                ebx
            //   56                   | push                esi

    condition:
        7 of them and filesize < 253952
}