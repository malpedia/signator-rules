rule win_grabbot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.grabbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.grabbot"
        malpedia_rule_date = "20220513"
        malpedia_hash = "7f4b2229e6ae614d86d74917f6d5b41890e62a26"
        malpedia_version = "20220516"
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
        $sequence_0 = { 83f85a 770b 83f841 7206 83c020 0fb7c0 83c202 }
            // n = 7, score = 3300
            //   83f85a               | cmp                 eax, 0x5a
            //   770b                 | ja                  0xd
            //   83f841               | cmp                 eax, 0x41
            //   7206                 | jb                  8
            //   83c020               | add                 eax, 0x20
            //   0fb7c0               | movzx               eax, ax
            //   83c202               | add                 edx, 2

        $sequence_1 = { 83f85a 770d 83f841 7208 }
            // n = 4, score = 3300
            //   83f85a               | cmp                 eax, 0x5a
            //   770d                 | ja                  0xf
            //   83f841               | cmp                 eax, 0x41
            //   7208                 | jb                  0xa

        $sequence_2 = { 50 e8???????? ffe0 c3 6827d9795d 6a00 }
            // n = 6, score = 3200
            //   50                   | push                eax
            //   e8????????           |                     
            //   ffe0                 | jmp                 eax
            //   c3                   | ret                 
            //   6827d9795d           | push                0x5d79d927
            //   6a00                 | push                0

        $sequence_3 = { 8908 83ea02 ebdf 58 034004 ebc3 83c410 }
            // n = 7, score = 3200
            //   8908                 | mov                 dword ptr [eax], ecx
            //   83ea02               | sub                 edx, 2
            //   ebdf                 | jmp                 0xffffffe1
            //   58                   | pop                 eax
            //   034004               | add                 eax, dword ptr [eax + 4]
            //   ebc3                 | jmp                 0xffffffc5
            //   83c410               | add                 esp, 0x10

        $sequence_4 = { 6683f807 7463 6683f80b 7571 0fb706 }
            // n = 5, score = 3200
            //   6683f807             | cmp                 ax, 7
            //   7463                 | je                  0x65
            //   6683f80b             | cmp                 ax, 0xb
            //   7571                 | jne                 0x73
            //   0fb706               | movzx               eax, word ptr [esi]

        $sequence_5 = { e8???????? ffd0 c3 682ef02a8f 6a00 6833320000 }
            // n = 6, score = 3200
            //   e8????????           |                     
            //   ffd0                 | call                eax
            //   c3                   | ret                 
            //   682ef02a8f           | push                0x8f2af02e
            //   6a00                 | push                0
            //   6833320000           | push                0x3233

        $sequence_6 = { 66ad 85d2 741b 6685c0 7411 }
            // n = 5, score = 3200
            //   66ad                 | lodsw               ax, word ptr [esi]
            //   85d2                 | test                edx, edx
            //   741b                 | je                  0x1d
            //   6685c0               | test                ax, ax
            //   7411                 | je                  0x13

        $sequence_7 = { 663bca 756b 8b8c18b0000000 85c9 7460 }
            // n = 5, score = 3200
            //   663bca               | cmp                 cx, dx
            //   756b                 | jne                 0x6d
            //   8b8c18b0000000       | mov                 ecx, dword ptr [eax + ebx + 0xb0]
            //   85c9                 | test                ecx, ecx
            //   7460                 | je                  0x62

        $sequence_8 = { 56 ffd0 33c9 66894c37fe }
            // n = 4, score = 2600
            //   56                   | push                esi
            //   ffd0                 | call                eax
            //   33c9                 | xor                 ecx, ecx
            //   66894c37fe           | mov                 word ptr [edi + esi - 2], cx

        $sequence_9 = { 7428 8b0d???????? 8908 8b0d???????? }
            // n = 4, score = 2300
            //   7428                 | je                  0x2a
            //   8b0d????????         |                     
            //   8908                 | mov                 dword ptr [eax], ecx
            //   8b0d????????         |                     

        $sequence_10 = { 8b0d???????? 894808 8b0d???????? 89480c e9???????? 33c0 }
            // n = 6, score = 2300
            //   8b0d????????         |                     
            //   894808               | mov                 dword ptr [eax + 8], ecx
            //   8b0d????????         |                     
            //   89480c               | mov                 dword ptr [eax + 0xc], ecx
            //   e9????????           |                     
            //   33c0                 | xor                 eax, eax

        $sequence_11 = { 8d45f0 99 52 50 8b451c 99 52 }
            // n = 7, score = 2000
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   99                   | cdq                 
            //   52                   | push                edx
            //   50                   | push                eax
            //   8b451c               | mov                 eax, dword ptr [ebp + 0x1c]
            //   99                   | cdq                 
            //   52                   | push                edx

        $sequence_12 = { 56 0f9fc3 e8???????? 83c414 5e 8ac3 5b }
            // n = 7, score = 2000
            //   56                   | push                esi
            //   0f9fc3               | setg                bl
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   5e                   | pop                 esi
            //   8ac3                 | mov                 al, bl
            //   5b                   | pop                 ebx

        $sequence_13 = { 741b 8d440002 50 e8???????? }
            // n = 4, score = 2000
            //   741b                 | je                  0x1d
            //   8d440002             | lea                 eax, [eax + eax + 2]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_14 = { ff15???????? 50 ff15???????? a3???????? 85c0 7505 83c8ff }
            // n = 7, score = 2000
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   a3????????           |                     
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7
            //   83c8ff               | or                  eax, 0xffffffff

        $sequence_15 = { 8bf0 85f6 741d 8d4601 50 e8???????? 8bf8 }
            // n = 7, score = 2000
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   741d                 | je                  0x1f
            //   8d4601               | lea                 eax, [esi + 1]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax

    condition:
        7 of them and filesize < 1335296
}