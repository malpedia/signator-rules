rule win_attor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.attor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.attor"
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
        $sequence_0 = { 83f801 7411 3d81000000 740a }
            // n = 4, score = 400
            //   83f801               | cmp                 eax, 1
            //   7411                 | je                  0x13
            //   3d81000000           | cmp                 eax, 0x81
            //   740a                 | je                  0xc

        $sequence_1 = { 4889442458 e8???????? 4839742440 745a b101 e8???????? }
            // n = 6, score = 300
            //   4889442458           | lea                 edx, [eax + 1]
            //   e8????????           |                     
            //   4839742440           | dec                 eax
            //   745a                 | mov                 dword ptr [edi + 0x20], eax
            //   b101                 | test                eax, eax
            //   e8????????           |                     

        $sequence_2 = { 418d5101 ff15???????? 85c0 750a }
            // n = 4, score = 300
            //   418d5101             | jne                 0x12
            //   ff15????????         |                     
            //   85c0                 | inc                 eax
            //   750a                 | xor                 ch, ch

        $sequence_3 = { 488b442440 c74004ffff1f00 488b4c2440 4883c108 e8???????? 488b742440 }
            // n = 6, score = 300
            //   488b442440           | cmp                 dword ptr [esp + 0x40], esi
            //   c74004ffff1f00       | je                  0x61
            //   488b4c2440           | mov                 cl, 1
            //   4883c108             | inc                 ecx
            //   e8????????           |                     
            //   488b742440           | lea                 edx, [ecx + 1]

        $sequence_4 = { 488907 48894708 48894710 48894718 8d5001 48894720 }
            // n = 6, score = 300
            //   488907               | jne                 0x12
            //   48894708             | inc                 eax
            //   48894710             | xor                 ch, ch
            //   48894718             | dec                 eax
            //   8d5001               | mov                 dword ptr [edi], eax
            //   48894720             | dec                 eax

        $sequence_5 = { 4885c9 0f84ad000000 4885d2 0f84a4000000 48895c2448 488d5a08 }
            // n = 6, score = 300
            //   4885c9               | mov                 ebx, eax
            //   0f84ad000000         | dec                 ebp
            //   4885d2               | test                edi, edi
            //   0f84a4000000         | dec                 eax
            //   48895c2448           | mov                 dword ptr [esp + 0x58], eax
            //   488d5a08             | dec                 eax

        $sequence_6 = { 488b0d???????? bae8030000 ff15???????? 85c0 }
            // n = 4, score = 300
            //   488b0d????????       |                     
            //   bae8030000           | test                eax, eax
            //   ff15????????         |                     
            //   85c0                 | jne                 0xe

        $sequence_7 = { 4c8bf0 4885c0 7510 ff15???????? 4032ed }
            // n = 5, score = 300
            //   4c8bf0               | dec                 esp
            //   4885c0               | mov                 esi, eax
            //   7510                 | dec                 eax
            //   ff15????????         |                     
            //   4032ed               | test                eax, eax

        $sequence_8 = { 85c0 743f c60011 8b442410 c6400103 }
            // n = 5, score = 200
            //   85c0                 | mov                 ebx, dword ptr [esp + 0x28]
            //   743f                 | cmp                 ebx, edi
            //   c60011               | jmp                 0x19
            //   8b442410             | mov                 dword ptr [esp + 0x14], 0x57
            //   c6400103             | mov                 dword ptr [esp + 0x14], eax

        $sequence_9 = { 897c2414 0f8423010000 8b5c2428 3bdf }
            // n = 4, score = 200
            //   897c2414             | dec                 eax
            //   0f8423010000         | mov                 ecx, dword ptr [esp + 0x40]
            //   8b5c2428             | dec                 eax
            //   3bdf                 | add                 ecx, 8

        $sequence_10 = { 83c40c 3bc7 8944241c 0f84f3000000 8b4c2424 8d6908 }
            // n = 6, score = 200
            //   83c40c               | mov                 ecx, dword ptr [esp + 0x30]
            //   3bc7                 | dec                 esp
            //   8944241c             | mov                 eax, ebp
            //   0f84f3000000         | xor                 edx, edx
            //   8b4c2424             | je                  0xc
            //   8d6908               | cmp                 eax, 8

        $sequence_11 = { 740a 83f808 7405 83f811 }
            // n = 4, score = 200
            //   740a                 | dec                 eax
            //   83f808               | test                edx, edx
            //   7405                 | je                  0xb3
            //   83f811               | dec                 eax

        $sequence_12 = { 53 8b5c242c 55 56 57 33ff }
            // n = 6, score = 200
            //   53                   | mov                 dword ptr [esp + 0x48], ebx
            //   8b5c242c             | dec                 eax
            //   55                   | lea                 ebx, [edx + 8]
            //   56                   | dec                 eax
            //   57                   | mov                 eax, dword ptr [esp + 0x40]
            //   33ff                 | mov                 dword ptr [eax + 4], 0x1fffff

        $sequence_13 = { 3bc7 0f844e020000 6a01 e8???????? }
            // n = 4, score = 200
            //   3bc7                 | xor                 edi, edi
            //   0f844e020000         | mov                 dword ptr [esp + 0x14], edi
            //   6a01                 | je                  0x12d
            //   e8????????           |                     

        $sequence_14 = { 8b4c241c 51 ffd6 83c408 897c2418 8b7c2424 85ff }
            // n = 7, score = 200
            //   8b4c241c             | je                  0xa
            //   51                   | cmp                 eax, 0x11
            //   ffd6                 | push                ebx
            //   83c408               | mov                 ebx, dword ptr [esp + 0x2c]
            //   897c2418             | push                ebp
            //   8b7c2424             | push                esi
            //   85ff                 | push                edi

        $sequence_15 = { eb17 c744241457000000 e9???????? ff15???????? 89442414 8b44241c 85c0 }
            // n = 7, score = 200
            //   eb17                 | dec                 eax
            //   c744241457000000     | mov                 esi, dword ptr [esp + 0x40]
            //   e9????????           |                     
            //   ff15????????         |                     
            //   89442414             | mov                 edx, 0x3e8
            //   8b44241c             | test                eax, eax
            //   85c0                 | dec                 eax

    condition:
        7 of them and filesize < 2023424
}