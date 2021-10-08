rule win_cobalt_strike_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.cobalt_strike."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"
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
        $sequence_0 = { e9???????? eb0a b801000000 e9???????? }
            // n = 4, score = 1400
            //   e9????????           |                     
            //   eb0a                 | jmp                 0xc
            //   b801000000           | mov                 eax, 1
            //   e9????????           |                     

        $sequence_1 = { 3bc7 750d ff15???????? 3d33270000 }
            // n = 4, score = 1400
            //   3bc7                 | cmp                 eax, edi
            //   750d                 | jne                 0xf
            //   ff15????????         |                     
            //   3d33270000           | cmp                 eax, 0x2733

        $sequence_2 = { e9???????? 833d????????01 7505 e8???????? }
            // n = 4, score = 1000
            //   e9????????           |                     
            //   833d????????01       |                     
            //   7505                 | jne                 7
            //   e8????????           |                     

        $sequence_3 = { 8bd0 e8???????? 85c0 7e0e }
            // n = 4, score = 1000
            //   8bd0                 | mov                 edx, eax
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7e0e                 | jle                 0x10

        $sequence_4 = { c3 55 8bec 57 683f000f00 6a00 6a00 }
            // n = 7, score = 900
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   57                   | push                edi
            //   683f000f00           | push                0xf003f
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_5 = { c1e008 0bc8 8b5508 0fb64213 25ff000000 0bc8 8b55d4 }
            // n = 7, score = 900
            //   c1e008               | shl                 eax, 8
            //   0bc8                 | or                  ecx, eax
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   0fb64213             | movzx               eax, byte ptr [edx + 0x13]
            //   25ff000000           | and                 eax, 0xff
            //   0bc8                 | or                  ecx, eax
            //   8b55d4               | mov                 edx, dword ptr [ebp - 0x2c]

        $sequence_6 = { c1e008 0bc8 8b5508 0fb64217 25ff000000 0bc8 8b55d4 }
            // n = 7, score = 900
            //   c1e008               | shl                 eax, 8
            //   0bc8                 | or                  ecx, eax
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   0fb64217             | movzx               eax, byte ptr [edx + 0x17]
            //   25ff000000           | and                 eax, 0xff
            //   0bc8                 | or                  ecx, eax
            //   8b55d4               | mov                 edx, dword ptr [ebp - 0x2c]

        $sequence_7 = { 8bd8 81c330750000 8365f800 c745fc64000000 e9???????? }
            // n = 5, score = 900
            //   8bd8                 | cmp                 eax, 0x2733
            //   81c330750000         | jmp                 0xc
            //   8365f800             | mov                 eax, 1
            //   c745fc64000000       | jne                 7
            //   e9????????           |                     

        $sequence_8 = { c1e008 0bc8 8b5508 0fb6420f 25ff000000 0bc8 8b55d4 }
            // n = 7, score = 900
            //   c1e008               | shl                 eax, 8
            //   0bc8                 | or                  ecx, eax
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   0fb6420f             | movzx               eax, byte ptr [edx + 0xf]
            //   25ff000000           | and                 eax, 0xff
            //   0bc8                 | or                  ecx, eax
            //   8b55d4               | mov                 edx, dword ptr [ebp - 0x2c]

        $sequence_9 = { 8b4d0c 884105 8b45ec c1e808 25ff000000 8b4d0c }
            // n = 6, score = 900
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   884105               | mov                 byte ptr [ecx + 5], al
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   c1e808               | shr                 eax, 8
            //   25ff000000           | and                 eax, 0xff
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]

        $sequence_10 = { e8???????? 85c0 753c 488d4ddf }
            // n = 4, score = 500
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   753c                 | jne                 0x3e
            //   488d4ddf             | dec                 eax

        $sequence_11 = { e8???????? eb21 8b17 4d8bc6 }
            // n = 4, score = 500
            //   e8????????           |                     
            //   eb21                 | mov                 edx, edx
            //   8b17                 | dec                 ecx
            //   4d8bc6               | mov                 ecx, ecx

        $sequence_12 = { e8???????? eb20 4c8d4538 418bd2 498bc9 }
            // n = 5, score = 500
            //   e8????????           |                     
            //   eb20                 | inc                 esp
            //   4c8d4538             | mov                 edi, dword ptr [ebp - 0x20]
            //   418bd2               | dec                 esp
            //   498bc9               | lea                 eax, dword ptr [ebp + 0x38]

        $sequence_13 = { e8???????? eb2f e8???????? 4d8bc2 }
            // n = 4, score = 500
            //   e8????????           |                     
            //   eb2f                 | test                eax, eax
            //   e8????????           |                     
            //   4d8bc2               | jne                 0x45

        $sequence_14 = { e8???????? 85c0 7541 448b7de0 }
            // n = 4, score = 500
            //   e8????????           |                     
            //   85c0                 | jne                 0x3e
            //   7541                 | dec                 esp
            //   448b7de0             | mov                 eax, dword ptr [edi + 0x10]

        $sequence_15 = { e8???????? eb21 4c8bc3 ba08000000 }
            // n = 4, score = 500
            //   e8????????           |                     
            //   eb21                 | jne                 0x43
            //   4c8bc3               | inc                 esp
            //   ba08000000           | mov                 edi, dword ptr [ebp - 0x20]

    condition:
        7 of them and filesize < 696320
}