rule win_korlia_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.korlia."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.korlia"
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
        $sequence_0 = { 6a32 50 ff15???????? 85c0 }
            // n = 4, score = 2400
            //   6a32                 | push                0x32
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_1 = { 83c9ff 33c0 f2ae f7d1 49 83f90f 7604 }
            // n = 7, score = 2200
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx
            //   83f90f               | cmp                 ecx, 0xf
            //   7604                 | jbe                 6

        $sequence_2 = { ffd6 8bc7 b9005c2605 99 f7f9 }
            // n = 5, score = 2200
            //   ffd6                 | call                esi
            //   8bc7                 | mov                 eax, edi
            //   b9005c2605           | mov                 ecx, 0x5265c00
            //   99                   | cdq                 
            //   f7f9                 | idiv                ecx

        $sequence_3 = { ff15???????? 8bd8 eb04 8b5c240c }
            // n = 4, score = 2200
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax
            //   eb04                 | jmp                 6
            //   8b5c240c             | mov                 ebx, dword ptr [esp + 0xc]

        $sequence_4 = { 8965e8 c645e401 c745fc00000000 52 51 }
            // n = 5, score = 2200
            //   8965e8               | mov                 dword ptr [ebp - 0x18], esp
            //   c645e401             | mov                 byte ptr [ebp - 0x1c], 1
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   52                   | push                edx
            //   51                   | push                ecx

        $sequence_5 = { ffd6 8bc7 b980ee3600 99 }
            // n = 4, score = 2200
            //   ffd6                 | call                esi
            //   8bc7                 | mov                 eax, edi
            //   b980ee3600           | mov                 ecx, 0x36ee80
            //   99                   | cdq                 

        $sequence_6 = { ed 81fb68584d56 0f9445e4 5b 59 5a c745fcffffffff }
            // n = 7, score = 2200
            //   ed                   | in                  eax, dx
            //   81fb68584d56         | cmp                 ebx, 0x564d5868
            //   0f9445e4             | sete                byte ptr [ebp - 0x1c]
            //   5b                   | pop                 ebx
            //   59                   | pop                 ecx
            //   5a                   | pop                 edx
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff

        $sequence_7 = { c3 85db 7410 6a28 68???????? }
            // n = 5, score = 2200
            //   c3                   | ret                 
            //   85db                 | test                ebx, ebx
            //   7410                 | je                  0x12
            //   6a28                 | push                0x28
            //   68????????           |                     

        $sequence_8 = { 6a01 53 53 53 51 ff15???????? 85c0 }
            // n = 7, score = 1900
            //   6a01                 | push                1
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_9 = { e8???????? 83c410 85c0 7f14 }
            // n = 4, score = 1500
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax
            //   7f14                 | jg                  0x16

        $sequence_10 = { 6a01 6a00 6a00 6800000040 50 ff15???????? 8bf0 }
            // n = 7, score = 700
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6800000040           | push                0x40000000
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_11 = { 8b442404 56 6a00 6a00 6a01 }
            // n = 5, score = 700
            //   8b442404             | mov                 eax, dword ptr [esp + 4]
            //   56                   | push                esi
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a01                 | push                1

        $sequence_12 = { ff15???????? 8bf0 83feff 7423 8b542410 8b44240c }
            // n = 6, score = 600
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   83feff               | cmp                 esi, -1
            //   7423                 | je                  0x25
            //   8b542410             | mov                 edx, dword ptr [esp + 0x10]
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]

        $sequence_13 = { f2ae f7d1 2bf9 6810270000 }
            // n = 4, score = 600
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   2bf9                 | sub                 edi, ecx
            //   6810270000           | push                0x2710

        $sequence_14 = { 7423 8b542410 8b44240c 8d4c2408 6a00 51 52 }
            // n = 7, score = 600
            //   7423                 | je                  0x25
            //   8b542410             | mov                 edx, dword ptr [esp + 0x10]
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   8d4c2408             | lea                 ecx, dword ptr [esp + 8]
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   52                   | push                edx

        $sequence_15 = { 50 56 ff15???????? 56 ff15???????? b001 5e }
            // n = 7, score = 600
            //   50                   | push                eax
            //   56                   | push                esi
            //   ff15????????         |                     
            //   56                   | push                esi
            //   ff15????????         |                     
            //   b001                 | mov                 al, 1
            //   5e                   | pop                 esi

        $sequence_16 = { 8bf9 81e7ff000000 03f2 03f7 }
            // n = 4, score = 500
            //   8bf9                 | mov                 edi, ecx
            //   81e7ff000000         | and                 edi, 0xff
            //   03f2                 | add                 esi, edx
            //   03f7                 | add                 esi, edi

        $sequence_17 = { 59 59 c3 8b65e8 ff7588 ff15???????? 833d????????ff }
            // n = 7, score = 500
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   8b65e8               | mov                 esp, dword ptr [ebp - 0x18]
            //   ff7588               | push                dword ptr [ebp - 0x78]
            //   ff15????????         |                     
            //   833d????????ff       |                     

        $sequence_18 = { 884814 8b4c240c 898840200000 58 c20800 e9???????? 6800060000 }
            // n = 7, score = 500
            //   884814               | mov                 byte ptr [eax + 0x14], cl
            //   8b4c240c             | mov                 ecx, dword ptr [esp + 0xc]
            //   898840200000         | mov                 dword ptr [eax + 0x2040], ecx
            //   58                   | pop                 eax
            //   c20800               | ret                 8
            //   e9????????           |                     
            //   6800060000           | push                0x600

        $sequence_19 = { 8d442444 894d00 8b542438 83c504 50 895500 }
            // n = 6, score = 500
            //   8d442444             | lea                 eax, dword ptr [esp + 0x44]
            //   894d00               | mov                 dword ptr [ebp], ecx
            //   8b542438             | mov                 edx, dword ptr [esp + 0x38]
            //   83c504               | add                 ebp, 4
            //   50                   | push                eax
            //   895500               | mov                 dword ptr [ebp], edx

        $sequence_20 = { ff7588 ff15???????? 833d????????ff 750c ff742404 ff15???????? }
            // n = 6, score = 500
            //   ff7588               | push                dword ptr [ebp - 0x78]
            //   ff15????????         |                     
            //   833d????????ff       |                     
            //   750c                 | jne                 0xe
            //   ff742404             | push                dword ptr [esp + 4]
            //   ff15????????         |                     

        $sequence_21 = { b8447c0000 e8???????? 53 56 57 }
            // n = 5, score = 500
            //   b8447c0000           | mov                 eax, 0x7c44
            //   e8????????           |                     
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_22 = { ff742410 e8???????? c21000 e8???????? 8a4c2404 6a01 884814 }
            // n = 7, score = 500
            //   ff742410             | push                dword ptr [esp + 0x10]
            //   e8????????           |                     
            //   c21000               | ret                 0x10
            //   e8????????           |                     
            //   8a4c2404             | mov                 cl, byte ptr [esp + 4]
            //   6a01                 | push                1
            //   884814               | mov                 byte ptr [eax + 0x14], cl

        $sequence_23 = { ffd6 8d44240c 6804010000 50 }
            // n = 4, score = 400
            //   ffd6                 | call                esi
            //   8d44240c             | lea                 eax, dword ptr [esp + 0xc]
            //   6804010000           | push                0x104
            //   50                   | push                eax

        $sequence_24 = { 83c504 50 895500 83c504 e8???????? d1e0 8bc8 }
            // n = 7, score = 400
            //   83c504               | add                 ebp, 4
            //   50                   | push                eax
            //   895500               | mov                 dword ptr [ebp], edx
            //   83c504               | add                 ebp, 4
            //   e8????????           |                     
            //   d1e0                 | shl                 eax, 1
            //   8bc8                 | mov                 ecx, eax

        $sequence_25 = { 6a00 6880000000 6800000400 8bce }
            // n = 4, score = 400
            //   6a00                 | push                0
            //   6880000000           | push                0x80
            //   6800000400           | push                0x40000
            //   8bce                 | mov                 ecx, esi

        $sequence_26 = { eb05 be00100000 8d442414 6a00 }
            // n = 4, score = 400
            //   eb05                 | jmp                 7
            //   be00100000           | mov                 esi, 0x1000
            //   8d442414             | lea                 eax, dword ptr [esp + 0x14]
            //   6a00                 | push                0

        $sequence_27 = { 6a00 6a00 6a00 6a00 50 8bce e8???????? }
            // n = 7, score = 400
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   50                   | push                eax
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_28 = { 51 ff15???????? a1???????? b981000000 }
            // n = 4, score = 400
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   a1????????           |                     
            //   b981000000           | mov                 ecx, 0x81

        $sequence_29 = { 1bc0 5e 24fe 5b 40 81c408010000 c3 }
            // n = 7, score = 300
            //   1bc0                 | sbb                 eax, eax
            //   5e                   | pop                 esi
            //   24fe                 | and                 al, 0xfe
            //   5b                   | pop                 ebx
            //   40                   | inc                 eax
            //   81c408010000         | add                 esp, 0x108
            //   c3                   | ret                 

        $sequence_30 = { 68ff0f1f00 ff15???????? 85c0 740a 56 50 ff15???????? }
            // n = 7, score = 300
            //   68ff0f1f00           | push                0x1f0fff
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   740a                 | je                  0xc
            //   56                   | push                esi
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_31 = { 56 57 b940000000 8d7c2411 }
            // n = 4, score = 300
            //   56                   | push                esi
            //   57                   | push                edi
            //   b940000000           | mov                 ecx, 0x40
            //   8d7c2411             | lea                 edi, dword ptr [esp + 0x11]

        $sequence_32 = { 50 ffd6 b912010000 33c0 }
            // n = 4, score = 300
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   b912010000           | mov                 ecx, 0x112
            //   33c0                 | xor                 eax, eax

        $sequence_33 = { 8bcb 83e103 f3a4 8d7c2410 83c9ff f2ae f7d1 }
            // n = 7, score = 300
            //   8bcb                 | mov                 ecx, ebx
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8d7c2410             | lea                 edi, dword ptr [esp + 0x10]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx

        $sequence_34 = { 8b4c2410 50 6a01 6a00 68???????? }
            // n = 5, score = 300
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   50                   | push                eax
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   68????????           |                     

        $sequence_35 = { 81ec08010000 8d442400 50 6806000200 }
            // n = 4, score = 300
            //   81ec08010000         | sub                 esp, 0x108
            //   8d442400             | lea                 eax, dword ptr [esp]
            //   50                   | push                eax
            //   6806000200           | push                0x20006

        $sequence_36 = { 33c0 8dbc245e020000 66899c245c020000 f3ab }
            // n = 4, score = 300
            //   33c0                 | xor                 eax, eax
            //   8dbc245e020000       | lea                 edi, dword ptr [esp + 0x25e]
            //   66899c245c020000     | mov                 word ptr [esp + 0x25c], bx
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax

        $sequence_37 = { 8d4c2410 6804010000 51 aa }
            // n = 4, score = 300
            //   8d4c2410             | lea                 ecx, dword ptr [esp + 0x10]
            //   6804010000           | push                0x104
            //   51                   | push                ecx
            //   aa                   | stosb               byte ptr es:[edi], al

        $sequence_38 = { 8b35???????? 50 ffd6 eb06 8b35???????? a1???????? }
            // n = 6, score = 300
            //   8b35????????         |                     
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   eb06                 | jmp                 8
            //   8b35????????         |                     
            //   a1????????           |                     

        $sequence_39 = { 3bc3 57 740b 8b35???????? 50 }
            // n = 5, score = 300
            //   3bc3                 | cmp                 eax, ebx
            //   57                   | push                edi
            //   740b                 | je                  0xd
            //   8b35????????         |                     
            //   50                   | push                eax

        $sequence_40 = { 8b4ddc 51 ffd3 8b55e4 52 ffd3 8b4df4 }
            // n = 7, score = 100
            //   8b4ddc               | mov                 ecx, dword ptr [ebp - 0x24]
            //   51                   | push                ecx
            //   ffd3                 | call                ebx
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]
            //   52                   | push                edx
            //   ffd3                 | call                ebx
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_41 = { ff15???????? 8d9654010000 8d8690010000 52 50 e8???????? }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   8d9654010000         | lea                 edx, dword ptr [esi + 0x154]
            //   8d8690010000         | lea                 eax, dword ptr [esi + 0x190]
            //   52                   | push                edx
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_42 = { 83c8ff 5b 81c480260000 c20400 55 8b2d???????? }
            // n = 6, score = 100
            //   83c8ff               | or                  eax, 0xffffffff
            //   5b                   | pop                 ebx
            //   81c480260000         | add                 esp, 0x2680
            //   c20400               | ret                 4
            //   55                   | push                ebp
            //   8b2d????????         |                     

        $sequence_43 = { 8975e8 ff15???????? 85f6 7439 8d4dd0 68???????? 51 }
            // n = 7, score = 100
            //   8975e8               | mov                 dword ptr [ebp - 0x18], esi
            //   ff15????????         |                     
            //   85f6                 | test                esi, esi
            //   7439                 | je                  0x3b
            //   8d4dd0               | lea                 ecx, dword ptr [ebp - 0x30]
            //   68????????           |                     
            //   51                   | push                ecx

    condition:
        7 of them and filesize < 163840
}