rule win_sedreco_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.sedreco."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sedreco"
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
        $sequence_0 = { 55 8bec 51 836d0804 53 56 8b750c }
            // n = 7, score = 2600
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   836d0804             | sub                 dword ptr [ebp + 8], 4
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]

        $sequence_1 = { c645ff30 e8???????? 85c0 7505 e8???????? }
            // n = 5, score = 2600
            //   c645ff30             | mov                 byte ptr [ebp - 1], 0x30
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7
            //   e8????????           |                     

        $sequence_2 = { e8???????? 89450c 56 85c0 }
            // n = 4, score = 2600
            //   e8????????           |                     
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   56                   | push                esi
            //   85c0                 | test                eax, eax

        $sequence_3 = { 8b750c 56 e8???????? 6a08 }
            // n = 4, score = 2600
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   56                   | push                esi
            //   e8????????           |                     
            //   6a08                 | push                8

        $sequence_4 = { 50 68???????? 6a0d 68???????? }
            // n = 4, score = 2500
            //   50                   | push                eax
            //   68????????           |                     
            //   6a0d                 | push                0xd
            //   68????????           |                     

        $sequence_5 = { 7411 6a04 68???????? 68???????? e8???????? }
            // n = 5, score = 2400
            //   7411                 | je                  0x13
            //   6a04                 | push                4
            //   68????????           |                     
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_6 = { 7ce0 a1???????? 5e 85c0 }
            // n = 4, score = 2400
            //   7ce0                 | jl                  0xffffffe2
            //   a1????????           |                     
            //   5e                   | pop                 esi
            //   85c0                 | test                eax, eax

        $sequence_7 = { 51 6802020000 68???????? 50 }
            // n = 4, score = 2400
            //   51                   | push                ecx
            //   6802020000           | push                0x202
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_8 = { e8???????? 83c40c b8f6eeeeee 8b4df0 }
            // n = 4, score = 2200
            //   e8????????           |                     
            //   83c40c               | test                eax, eax
            //   b8f6eeeeee           | jne                 9
            //   8b4df0               | jl                  0xffffffe2

        $sequence_9 = { 83c40c b8f2eeeeee 8b4df0 64890d00000000 59 5f }
            // n = 6, score = 2200
            //   83c40c               | push                ecx
            //   b8f2eeeeee           | sub                 dword ptr [ebp + 8], 4
            //   8b4df0               | push                ebx
            //   64890d00000000       | mov                 esi, dword ptr [ebp + 0xc]
            //   59                   | push                esi
            //   5f                   | push                8

        $sequence_10 = { 85f6 7429 6afe 8d45f0 }
            // n = 4, score = 2200
            //   85f6                 | mov                 esi, dword ptr [ebp + 0xc]
            //   7429                 | push                esi
            //   6afe                 | push                8
            //   8d45f0               | mov                 byte ptr [ebp - 1], 0x30

        $sequence_11 = { 85c0 7505 5b 33c0 5e c3 }
            // n = 6, score = 2200
            //   85c0                 | mov                 byte ptr [ebp - 1], 0x30
            //   7505                 | test                eax, eax
            //   5b                   | jne                 9
            //   33c0                 | push                ebp
            //   5e                   | mov                 ebp, esp
            //   c3                   | push                ecx

        $sequence_12 = { 68???????? 57 50 a1???????? }
            // n = 4, score = 1900
            //   68????????           |                     
            //   57                   | mov                 ebp, esp
            //   50                   | push                ecx
            //   a1????????           |                     

        $sequence_13 = { 51 ffd6 a3???????? 85c0 }
            // n = 4, score = 1500
            //   51                   | push                esi
            //   ffd6                 | mov                 esi, dword ptr [ebp + 0xc]
            //   a3????????           |                     
            //   85c0                 | mov                 byte ptr [ebp - 1], 0x30

        $sequence_14 = { 6a01 68???????? ff35???????? ff15???????? ffd0 }
            // n = 5, score = 1100
            //   6a01                 | push                ecx
            //   68????????           |                     
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   ffd0                 | sub                 dword ptr [ebp + 8], 4

        $sequence_15 = { 68???????? e8???????? 8b35???????? 83c404 6a00 }
            // n = 5, score = 500
            //   68????????           |                     
            //   e8????????           |                     
            //   8b35????????         |                     
            //   83c404               | push                0x200
            //   6a00                 | add                 esp, 4

        $sequence_16 = { 488b05???????? ff90e8000000 488b0d???????? 488b05???????? ff5028 }
            // n = 5, score = 500
            //   488b05????????       |                     
            //   ff90e8000000         | add                 esp, 0x28
            //   488b0d????????       |                     
            //   488b05????????       |                     
            //   ff5028               | ret                 

        $sequence_17 = { 68???????? 6aff 68???????? 6a00 6a00 ffd6 8b4dfc }
            // n = 7, score = 500
            //   68????????           |                     
            //   6aff                 | mov                 ebp, esp
            //   68????????           |                     
            //   6a00                 | push                ecx
            //   6a00                 | sub                 dword ptr [ebp + 8], 4
            //   ffd6                 | mov                 esi, dword ptr [ebp + 0xc]
            //   8b4dfc               | push                esi

        $sequence_18 = { 488b05???????? ff90e0000000 488b0d???????? 488b05???????? }
            // n = 4, score = 500
            //   488b05????????       |                     
            //   ff90e0000000         | xor                 ecx, ecx
            //   488b0d????????       |                     
            //   488b05????????       |                     

        $sequence_19 = { 4883c010 4883c428 c3 48890d???????? }
            // n = 4, score = 500
            //   4883c010             | call                dword ptr [eax + 0x40]
            //   4883c428             | call                dword ptr [eax + 0xe0]
            //   c3                   | call                dword ptr [eax + 0xe8]
            //   48890d????????       |                     

        $sequence_20 = { 6800010000 6a00 68???????? e8???????? 6800020000 6a00 68???????? }
            // n = 7, score = 500
            //   6800010000           | push                0
            //   6a00                 | call                esi
            //   68????????           |                     
            //   e8????????           |                     
            //   6800020000           | mov                 ecx, dword ptr [ebp - 4]
            //   6a00                 | pop                 edi
            //   68????????           |                     

        $sequence_21 = { 83c404 6a00 68???????? 6aff }
            // n = 4, score = 500
            //   83c404               | jne                 9
            //   6a00                 | mov                 ebp, esp
            //   68????????           |                     
            //   6aff                 | push                ecx

        $sequence_22 = { e8???????? c705????????01000000 33c0 4883c428 c3 48895c2408 57 }
            // n = 7, score = 500
            //   e8????????           |                     
            //   c705????????01000000     |     
            //   33c0                 | call                dword ptr [eax + 0xe8]
            //   4883c428             | mov                 edx, 0x2710
            //   c3                   | call                dword ptr [eax + 0x10]
            //   48895c2408           | test                eax, eax
            //   57                   | dec                 eax

        $sequence_23 = { 488b05???????? ff90e8000000 ba10270000 488b0d???????? }
            // n = 4, score = 500
            //   488b05????????       |                     
            //   ff90e8000000         | xor                 edx, edx
            //   ba10270000           | dec                 eax
            //   488b0d????????       |                     

        $sequence_24 = { c744242004000000 4533c9 4533c0 ba000000c0 488b0d???????? 488b05???????? ff5040 }
            // n = 7, score = 500
            //   c744242004000000     | mov                 ecx, eax
            //   4533c9               | call                dword ptr [eax + 0xe8]
            //   4533c0               | mov                 edx, 0x2710
            //   ba000000c0           | mov                 dword ptr [esp + 0x20], 4
            //   488b0d????????       |                     
            //   488b05????????       |                     
            //   ff5040               | inc                 ebp

        $sequence_25 = { ffd6 50 68???????? 6aff 68???????? }
            // n = 5, score = 500
            //   ffd6                 | push                8
            //   50                   | push                ebp
            //   68????????           |                     
            //   6aff                 | mov                 ebp, esp
            //   68????????           |                     

        $sequence_26 = { 4533c9 4533c0 33d2 488bc8 488b05???????? }
            // n = 5, score = 500
            //   4533c9               | inc                 ebp
            //   4533c0               | xor                 ecx, ecx
            //   33d2                 | inc                 ebp
            //   488bc8               | xor                 eax, eax
            //   488b05????????       |                     

        $sequence_27 = { 4889442420 41b906000200 4533c0 488b15???????? }
            // n = 4, score = 500
            //   4889442420           | mov                 edx, 0x2710
            //   41b906000200         | call                dword ptr [eax + 0x10]
            //   4533c0               | dec                 eax
            //   488b15????????       |                     

        $sequence_28 = { ffd6 8b4dfc 5f 5e 33cd b8???????? }
            // n = 6, score = 400
            //   ffd6                 | push                0
            //   8b4dfc               | push                -1
            //   5f                   | add                 esp, 4
            //   5e                   | push                0
            //   33cd                 | push                -1
            //   b8????????           |                     

        $sequence_29 = { 7cd5 68???????? e8???????? 8b4dfc 83c404 }
            // n = 5, score = 400
            //   7cd5                 | push                -1
            //   68????????           |                     
            //   e8????????           |                     
            //   8b4dfc               | push                0x100
            //   83c404               | push                0

        $sequence_30 = { ff15???????? 33c9 6685c0 0f95c1 8bc1 }
            // n = 5, score = 300
            //   ff15????????         |                     
            //   33c9                 | mov                 ecx, dword ptr [ebp - 4]
            //   6685c0               | pop                 edi
            //   0f95c1               | pop                 esi
            //   8bc1                 | xor                 ecx, ebp

        $sequence_31 = { 57 50 ff512c 8bce }
            // n = 4, score = 200
            //   57                   | push                edi
            //   50                   | mov                 dword ptr [ebp - 0x24], 0x54af97e1
            //   ff512c               | push                eax
            //   8bce                 | mov                 ecx, dword ptr [eax]

        $sequence_32 = { 6a06 6a02 6a00 6a00 6800000040 68???????? }
            // n = 6, score = 200
            //   6a06                 | mov                 ecx, dword ptr [ebp - 0x10]
            //   6a02                 | mov                 dword ptr fs:[0], ecx
            //   6a00                 | pop                 ecx
            //   6a00                 | pop                 edi
            //   6800000040           | test                eax, eax
            //   68????????           |                     

        $sequence_33 = { 53 56 57 c785ecfeffff01000000 c785e8feffffe197af54 0f6e85e8feffff }
            // n = 6, score = 200
            //   53                   | add                 esp, 0xc
            //   56                   | mov                 eax, 0xeeeeeef6
            //   57                   | mov                 ecx, dword ptr [ebp - 0x10]
            //   c785ecfeffff01000000     | je    0x54
            //   c785e8feffffe197af54     | push    -2
            //   0f6e85e8feffff       | lea                 eax, dword ptr [ebp - 0x10]

        $sequence_34 = { ff15???????? 83c41c e8???????? 8945f8 }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   83c41c               | mov                 eax, dword ptr [esi]
            //   e8????????           |                     
            //   8945f8               | push                eax

        $sequence_35 = { 8d443001 6a00 51 50 56 57 }
            // n = 6, score = 200
            //   8d443001             | call                dword ptr [ecx + 0x2c]
            //   6a00                 | mov                 ecx, esi
            //   51                   | call                dword ptr [ecx + 0x2c]
            //   50                   | mov                 esi, eax
            //   56                   | neg                 esi
            //   57                   | sbb                 esi, esi

        $sequence_36 = { ff512c 8bf0 f7de 1bf6 46 }
            // n = 5, score = 200
            //   ff512c               | call                dword ptr [ecx + 0x80]
            //   8bf0                 | mov                 eax, dword ptr [esi]
            //   f7de                 | test                eax, eax
            //   1bf6                 | push                ebx
            //   46                   | push                esi

        $sequence_37 = { 50 8b08 ff9180000000 8b06 85c0 }
            // n = 5, score = 200
            //   50                   | mov                 ecx, dword ptr [ebp - 0x10]
            //   8b08                 | mov                 dword ptr fs:[0], ecx
            //   ff9180000000         | pop                 ecx
            //   8b06                 | pop                 edi
            //   85c0                 | pop                 esi

        $sequence_38 = { 55 8bec 83ec24 53 56 57 c745dce197af54 }
            // n = 7, score = 200
            //   55                   | jne                 9
            //   8bec                 | pop                 ebx
            //   83ec24               | xor                 eax, eax
            //   53                   | pop                 esi
            //   56                   | ret                 
            //   57                   | add                 esp, 0xc
            //   c745dce197af54       | mov                 eax, 0xeeeeeef7

        $sequence_39 = { c0e906 88442417 8d4601 02d9 89442440 85c0 }
            // n = 6, score = 100
            //   c0e906               | push                0
            //   88442417             | call                esi
            //   8d4601               | mov                 ecx, dword ptr [ebp - 4]
            //   02d9                 | pop                 edi
            //   89442440             | pop                 esi
            //   85c0                 | jl                  0xffffffd7

        $sequence_40 = { 83fe01 7238 8b3d???????? 56 0fbee8 }
            // n = 5, score = 100
            //   83fe01               | pop                 esi
            //   7238                 | xor                 ecx, ebp
            //   8b3d????????         |                     
            //   56                   | pop                 ebx
            //   0fbee8               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_41 = { c684244010000002 8b0a 51 56 50 8d4c2424 }
            // n = 6, score = 100
            //   c684244010000002     | push                0
            //   8b0a                 | call                esi
            //   51                   | mov                 ecx, dword ptr [ebp - 4]
            //   56                   | pop                 edi
            //   50                   | pop                 esi
            //   8d4c2424             | xor                 ecx, ebp

        $sequence_42 = { 897e08 897e0c 8b15???????? 8d4c2424 }
            // n = 4, score = 100
            //   897e08               | push                0
            //   897e0c               | pop                 ebx
            //   8b15????????         |                     
            //   8d4c2424             | push                0x100

        $sequence_43 = { 85c0 7423 8a10 8d4c2448 3a11 0f8418010000 }
            // n = 6, score = 100
            //   85c0                 | mov                 ecx, dword ptr [ebp - 4]
            //   7423                 | pop                 edi
            //   8a10                 | pop                 esi
            //   8d4c2448             | xor                 ecx, ebp
            //   3a11                 | pop                 ebx
            //   0f8418010000         | push                0

        $sequence_44 = { 8d4da8 8845a8 ff15???????? 8bfe 83c9ff 33c0 f2ae }
            // n = 7, score = 100
            //   8d4da8               | mov                 ecx, dword ptr [ebp - 4]
            //   8845a8               | push                0
            //   ff15????????         |                     
            //   8bfe                 | call                esi
            //   83c9ff               | mov                 ecx, dword ptr [ebp - 4]
            //   33c0                 | pop                 edi
            //   f2ae                 | pop                 esi

        $sequence_45 = { ff15???????? 8b4dd4 885dfc 3bcb }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   8b4dd4               | xor                 ecx, ebp
            //   885dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   3bcb                 | pop                 edi

        $sequence_46 = { 8d4da8 8d5588 51 68???????? 52 }
            // n = 5, score = 100
            //   8d4da8               | jl                  0xffffffd7
            //   8d5588               | mov                 ecx, dword ptr [ebp - 4]
            //   51                   | add                 esp, 4
            //   68????????           |                     
            //   52                   | call                esi

    condition:
        7 of them and filesize < 1586176
}