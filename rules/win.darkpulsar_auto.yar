rule win_darkpulsar_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.darkpulsar."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkpulsar"
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
        $sequence_0 = { ff25???????? ff25???????? ff25???????? 33c0 40 c20c00 68???????? }
            // n = 7, score = 600
            //   ff25????????         |                     
            //   ff25????????         |                     
            //   ff25????????         |                     
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax
            //   c20c00               | ret                 0xc
            //   68????????           |                     

        $sequence_1 = { 40 c20c00 68???????? 64ff3500000000 8b442410 896c2410 8d6c2410 }
            // n = 7, score = 600
            //   40                   | inc                 eax
            //   c20c00               | ret                 0xc
            //   68????????           |                     
            //   64ff3500000000       | push                dword ptr fs:[0]
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   896c2410             | mov                 dword ptr [esp + 0x10], ebp
            //   8d6c2410             | lea                 ebp, dword ptr [esp + 0x10]

        $sequence_2 = { 3a01 1bc0 83e0fe 40 5f }
            // n = 5, score = 400
            //   3a01                 | cmp                 al, byte ptr [ecx]
            //   1bc0                 | sbb                 eax, eax
            //   83e0fe               | and                 eax, 0xfffffffe
            //   40                   | inc                 eax
            //   5f                   | pop                 edi

        $sequence_3 = { 47 ff450c 0fbe07 50 ffd6 }
            // n = 5, score = 300
            //   47                   | inc                 edi
            //   ff450c               | inc                 dword ptr [ebp + 0xc]
            //   0fbe07               | movsx               eax, byte ptr [edi]
            //   50                   | push                eax
            //   ffd6                 | call                esi

        $sequence_4 = { 59 3bd8 74e0 0fb607 8b4d0c }
            // n = 5, score = 300
            //   59                   | pop                 ecx
            //   3bd8                 | cmp                 ebx, eax
            //   74e0                 | je                  0xffffffe2
            //   0fb607               | movzx               eax, byte ptr [edi]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]

        $sequence_5 = { 8b450c 0fbe00 50 ffd6 59 59 3bd8 }
            // n = 7, score = 300
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   0fbe00               | movsx               eax, byte ptr [eax]
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   3bd8                 | cmp                 ebx, eax

        $sequence_6 = { 50 ffd6 8bd8 8b450c 0fbe00 }
            // n = 5, score = 300
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   8bd8                 | mov                 ebx, eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   0fbe00               | movsx               eax, byte ptr [eax]

        $sequence_7 = { 8b35???????? 57 8b7d08 eb09 }
            // n = 4, score = 300
            //   8b35????????         |                     
            //   57                   | push                edi
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   eb09                 | jmp                 0xb

        $sequence_8 = { 8b7d08 eb09 803f00 742e 47 }
            // n = 5, score = 300
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   eb09                 | jmp                 0xb
            //   803f00               | cmp                 byte ptr [edi], 0
            //   742e                 | je                  0x30
            //   47                   | inc                 edi

        $sequence_9 = { 0fb607 8b4d0c 3a01 1bc0 }
            // n = 4, score = 300
            //   0fb607               | movzx               eax, byte ptr [edi]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   3a01                 | cmp                 al, byte ptr [ecx]
            //   1bc0                 | sbb                 eax, eax

        $sequence_10 = { 56 e8???????? 59 85c0 7625 }
            // n = 5, score = 200
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   7625                 | jbe                 0x27

        $sequence_11 = { 8b5d10 56 8b7508 33d2 }
            // n = 4, score = 200
            //   8b5d10               | mov                 ebx, dword ptr [ebp + 0x10]
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   33d2                 | xor                 edx, edx

        $sequence_12 = { ab 8b7d08 57 e8???????? }
            // n = 4, score = 200
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_13 = { 8d45cc 50 57 e8???????? 83c410 85c0 }
            // n = 6, score = 200
            //   8d45cc               | lea                 eax, dword ptr [ebp - 0x34]
            //   50                   | push                eax
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax

        $sequence_14 = { 8d45d4 50 8d45e0 50 ff7510 }
            // n = 5, score = 200
            //   8d45d4               | lea                 eax, dword ptr [ebp - 0x2c]
            //   50                   | push                eax
            //   8d45e0               | lea                 eax, dword ptr [ebp - 0x20]
            //   50                   | push                eax
            //   ff7510               | push                dword ptr [ebp + 0x10]

        $sequence_15 = { 6a01 50 ff15???????? 8bf0 59 }
            // n = 5, score = 200
            //   6a01                 | push                1
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   59                   | pop                 ecx

        $sequence_16 = { e8???????? 59 5e 83f8ff }
            // n = 4, score = 200
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   5e                   | pop                 esi
            //   83f8ff               | cmp                 eax, -1

        $sequence_17 = { e8???????? 83c40c 013e e9???????? }
            // n = 4, score = 200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   013e                 | add                 dword ptr [esi], edi
            //   e9????????           |                     

        $sequence_18 = { 53 33d2 56 57 33c0 }
            // n = 5, score = 200
            //   53                   | push                ebx
            //   33d2                 | xor                 edx, edx
            //   56                   | push                esi
            //   57                   | push                edi
            //   33c0                 | xor                 eax, eax

        $sequence_19 = { ff742414 ff742414 e8???????? 83c414 c3 6a02 ff742410 }
            // n = 7, score = 200
            //   ff742414             | push                dword ptr [esp + 0x14]
            //   ff742414             | push                dword ptr [esp + 0x14]
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   c3                   | ret                 
            //   6a02                 | push                2
            //   ff742410             | push                dword ptr [esp + 0x10]

        $sequence_20 = { 59 5e 8b45fc c9 c3 }
            // n = 5, score = 200
            //   59                   | pop                 ecx
            //   5e                   | pop                 esi
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   c9                   | leave               
            //   c3                   | ret                 

        $sequence_21 = { ff7508 893e e8???????? 83c40c }
            // n = 4, score = 200
            //   ff7508               | push                dword ptr [ebp + 8]
            //   893e                 | mov                 dword ptr [esi], edi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_22 = { 51 8365fc00 837d0800 56 }
            // n = 4, score = 200
            //   51                   | push                ecx
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   56                   | push                esi

        $sequence_23 = { 33c0 33d2 c3 8bff 55 8bec b863736de0 }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   33d2                 | xor                 edx, edx
            //   c3                   | ret                 
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   b863736de0           | mov                 eax, 0xe06d7363

        $sequence_24 = { 8d4d0c 51 50 ff7508 e8???????? }
            // n = 5, score = 200
            //   8d4d0c               | lea                 ecx, dword ptr [ebp + 0xc]
            //   51                   | push                ecx
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     

        $sequence_25 = { 83c410 83f8ff 0f95c1 49 }
            // n = 4, score = 200
            //   83c410               | add                 esp, 0x10
            //   83f8ff               | cmp                 eax, -1
            //   0f95c1               | setne               cl
            //   49                   | dec                 ecx

        $sequence_26 = { ffd7 59 5f 5e c3 8b4c2404 85c9 }
            // n = 7, score = 200
            //   ffd7                 | call                edi
            //   59                   | pop                 ecx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   8b4c2404             | mov                 ecx, dword ptr [esp + 4]
            //   85c9                 | test                ecx, ecx

        $sequence_27 = { 8bf0 46 56 ff15???????? 59 }
            // n = 5, score = 200
            //   8bf0                 | mov                 esi, eax
            //   46                   | inc                 esi
            //   56                   | push                esi
            //   ff15????????         |                     
            //   59                   | pop                 ecx

        $sequence_28 = { 8d4207 5e 8b7c2414 8808 0facf908 }
            // n = 5, score = 100
            //   8d4207               | lea                 eax, dword ptr [edx + 7]
            //   5e                   | pop                 esi
            //   8b7c2414             | mov                 edi, dword ptr [esp + 0x14]
            //   8808                 | mov                 byte ptr [eax], cl
            //   0facf908             | shrd                ecx, edi, 8

        $sequence_29 = { 837d9c00 741c 837d0c07 7416 }
            // n = 4, score = 100
            //   837d9c00             | cmp                 dword ptr [ebp - 0x64], 0
            //   741c                 | je                  0x1e
            //   837d0c07             | cmp                 dword ptr [ebp + 0xc], 7
            //   7416                 | je                  0x18

        $sequence_30 = { 33c5 8945fc 8d8588feffff 50 }
            // n = 4, score = 100
            //   33c5                 | xor                 eax, ebp
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8d8588feffff         | lea                 eax, dword ptr [ebp - 0x178]
            //   50                   | push                eax

        $sequence_31 = { 8d458c 6a00 50 c7458800000000 e8???????? 8b7518 8b4d0c }
            // n = 7, score = 100
            //   8d458c               | lea                 eax, dword ptr [ebp - 0x74]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   c7458800000000       | mov                 dword ptr [ebp - 0x78], 0
            //   e8????????           |                     
            //   8b7518               | mov                 esi, dword ptr [ebp + 0x18]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]

        $sequence_32 = { 0f840ffeffff 6a01 8d55dd 52 8d45cc 50 57 }
            // n = 7, score = 100
            //   0f840ffeffff         | je                  0xfffffe15
            //   6a01                 | push                1
            //   8d55dd               | lea                 edx, dword ptr [ebp - 0x23]
            //   52                   | push                edx
            //   8d45cc               | lea                 eax, dword ptr [ebp - 0x34]
            //   50                   | push                eax
            //   57                   | push                edi

        $sequence_33 = { 8808 83c004 c3 e9???????? 8b542404 }
            // n = 5, score = 100
            //   8808                 | mov                 byte ptr [eax], cl
            //   83c004               | add                 eax, 4
            //   c3                   | ret                 
            //   e9????????           |                     
            //   8b542404             | mov                 edx, dword ptr [esp + 4]

        $sequence_34 = { e8???????? 8d45f4 50 e8???????? 8bca 83c40c }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8d45f4               | lea                 eax, dword ptr [ebp - 0xc]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bca                 | mov                 ecx, edx
            //   83c40c               | add                 esp, 0xc

        $sequence_35 = { 00db 7313 75e1 3b742404 0f8318010000 }
            // n = 5, score = 100
            //   00db                 | add                 bl, bl
            //   7313                 | jae                 0x15
            //   75e1                 | jne                 0xffffffe3
            //   3b742404             | cmp                 esi, dword ptr [esp + 4]
            //   0f8318010000         | jae                 0x11e

        $sequence_36 = { 8908 33c0 c9 c3 83c8ff c9 c3 }
            // n = 7, score = 100
            //   8908                 | mov                 dword ptr [eax], ecx
            //   33c0                 | xor                 eax, eax
            //   c9                   | leave               
            //   c3                   | ret                 
            //   83c8ff               | or                  eax, 0xffffffff
            //   c9                   | leave               
            //   c3                   | ret                 

        $sequence_37 = { 00db 73e1 7511 3b742404 }
            // n = 4, score = 100
            //   00db                 | add                 bl, bl
            //   73e1                 | jae                 0xffffffe3
            //   7511                 | jne                 0x13
            //   3b742404             | cmp                 esi, dword ptr [esp + 4]

        $sequence_38 = { 744a 8d45dc 50 57 ff15???????? 59 59 }
            // n = 7, score = 100
            //   744a                 | je                  0x4c
            //   8d45dc               | lea                 eax, dword ptr [ebp - 0x24]
            //   50                   | push                eax
            //   57                   | push                edi
            //   ff15????????         |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx

        $sequence_39 = { 83c40c 6a04 8d4dec 51 }
            // n = 4, score = 100
            //   83c40c               | add                 esp, 0xc
            //   6a04                 | push                4
            //   8d4dec               | lea                 ecx, dword ptr [ebp - 0x14]
            //   51                   | push                ecx

        $sequence_40 = { 00db 7313 752f 3b742404 0f830b010000 }
            // n = 5, score = 100
            //   00db                 | add                 bl, bl
            //   7313                 | jae                 0x15
            //   752f                 | jne                 0x31
            //   3b742404             | cmp                 esi, dword ptr [esp + 4]
            //   0f830b010000         | jae                 0x111

        $sequence_41 = { eb36 dd05???????? 8d45f4 50 51 51 }
            // n = 6, score = 100
            //   eb36                 | jmp                 0x38
            //   dd05????????         |                     
            //   8d45f4               | lea                 eax, dword ptr [ebp - 0xc]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   51                   | push                ecx

        $sequence_42 = { ff15???????? 83c41c 85c0 7405 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   83c41c               | add                 esp, 0x1c
            //   85c0                 | test                eax, eax
            //   7405                 | je                  7

        $sequence_43 = { ff7510 53 ffd6 53 ffd7 83c410 }
            // n = 6, score = 100
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   53                   | push                ebx
            //   ffd6                 | call                esi
            //   53                   | push                ebx
            //   ffd7                 | call                edi
            //   83c410               | add                 esp, 0x10

        $sequence_44 = { 8945d8 8b450c 897de8 897ddc }
            // n = 4, score = 100
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   897de8               | mov                 dword ptr [ebp - 0x18], edi
            //   897ddc               | mov                 dword ptr [ebp - 0x24], edi

        $sequence_45 = { 8d45f0 68???????? 50 ff15???????? 6a02 8d45f0 }
            // n = 6, score = 100
            //   8d45f0               | lea                 eax, dword ptr [ebp - 0x10]
            //   68????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   6a02                 | push                2
            //   8d45f0               | lea                 eax, dword ptr [ebp - 0x10]

        $sequence_46 = { 57 50 e8???????? 83c418 894648 85c0 }
            // n = 6, score = 100
            //   57                   | push                edi
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   894648               | mov                 dword ptr [esi + 0x48], eax
            //   85c0                 | test                eax, eax

        $sequence_47 = { e8???????? eb25 8b8528f4ffff 8b4810 68???????? }
            // n = 5, score = 100
            //   e8????????           |                     
            //   eb25                 | jmp                 0x27
            //   8b8528f4ffff         | mov                 eax, dword ptr [ebp - 0xbd8]
            //   8b4810               | mov                 ecx, dword ptr [eax + 0x10]
            //   68????????           |                     

        $sequence_48 = { 8306ec 83c40c 8d55e8 52 56 8bcb e8???????? }
            // n = 7, score = 100
            //   8306ec               | add                 dword ptr [esi], -0x14
            //   83c40c               | add                 esp, 0xc
            //   8d55e8               | lea                 edx, dword ptr [ebp - 0x18]
            //   52                   | push                edx
            //   56                   | push                esi
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     

        $sequence_49 = { 56 8b742410 880411 0facf008 41 c1ee08 }
            // n = 6, score = 100
            //   56                   | push                esi
            //   8b742410             | mov                 esi, dword ptr [esp + 0x10]
            //   880411               | mov                 byte ptr [ecx + edx], al
            //   0facf008             | shrd                eax, esi, 8
            //   41                   | inc                 ecx
            //   c1ee08               | shr                 esi, 8

        $sequence_50 = { 00db 7309 75f4 8a1e 46 10db }
            // n = 6, score = 100
            //   00db                 | add                 bl, bl
            //   7309                 | jae                 0xb
            //   75f4                 | jne                 0xfffffff6
            //   8a1e                 | mov                 bl, byte ptr [esi]
            //   46                   | inc                 esi
            //   10db                 | adc                 bl, bl

    condition:
        7 of them and filesize < 491520
}