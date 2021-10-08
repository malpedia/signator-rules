rule win_compfun_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.compfun."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.compfun"
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
        $sequence_0 = { e8???????? 83c40c c746247d202020 c70642434445 c7460430333935 c746082d453532 }
            // n = 6, score = 300
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   c746247d202020       | mov                 dword ptr [esi + 0x24], 0x2020207d
            //   c70642434445         | mov                 dword ptr [esi], 0x45444342
            //   c7460430333935       | mov                 dword ptr [esi + 4], 0x35393330
            //   c746082d453532       | mov                 dword ptr [esi + 8], 0x3235452d

        $sequence_1 = { 83c40c c70643726561 c746047465546f c746086f6c6865 c7460c6c703332 }
            // n = 5, score = 300
            //   83c40c               | add                 esp, 0xc
            //   c70643726561         | mov                 dword ptr [esi], 0x61657243
            //   c746047465546f       | mov                 dword ptr [esi + 4], 0x6f546574
            //   c746086f6c6865       | mov                 dword ptr [esi + 8], 0x65686c6f
            //   c7460c6c703332       | mov                 dword ptr [esi + 0xc], 0x3233706c

        $sequence_2 = { e8???????? 83c40c c70647657446 c74604756c6c50 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   c70647657446         | mov                 dword ptr [esi], 0x46746547
            //   c74604756c6c50       | mov                 dword ptr [esi + 4], 0x506c6c75

        $sequence_3 = { c70643726561 c7460474655265 c746086d6f7465 c7460c54687265 c6461200 }
            // n = 5, score = 300
            //   c70643726561         | mov                 dword ptr [esi], 0x61657243
            //   c7460474655265       | mov                 dword ptr [esi + 4], 0x65526574
            //   c746086d6f7465       | mov                 dword ptr [esi + 8], 0x65746f6d
            //   c7460c54687265       | mov                 dword ptr [esi + 0xc], 0x65726854
            //   c6461200             | mov                 byte ptr [esi + 0x12], 0

        $sequence_4 = { c7064d4d4465 c7460476696365 c74608456e756d c7460c65726174 c746106f722063 c746146c617373 }
            // n = 6, score = 300
            //   c7064d4d4465         | mov                 dword ptr [esi], 0x65444d4d
            //   c7460476696365       | mov                 dword ptr [esi + 4], 0x65636976
            //   c74608456e756d       | mov                 dword ptr [esi + 8], 0x6d756e45
            //   c7460c65726174       | mov                 dword ptr [esi + 0xc], 0x74617265
            //   c746106f722063       | mov                 dword ptr [esi + 0x10], 0x6320726f
            //   c746146c617373       | mov                 dword ptr [esi + 0x14], 0x7373616c

        $sequence_5 = { c7460475657279 c7460856616c75 c7460c65457857 c6461000 8bc6 5e }
            // n = 6, score = 300
            //   c7460475657279       | mov                 dword ptr [esi + 4], 0x79726575
            //   c7460856616c75       | mov                 dword ptr [esi + 8], 0x756c6156
            //   c7460c65457857       | mov                 dword ptr [esi + 0xc], 0x57784565
            //   c6461000             | mov                 byte ptr [esi + 0x10], 0
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi

        $sequence_6 = { c746087446696c c6460e00 8bc6 5e 5d }
            // n = 5, score = 300
            //   c746087446696c       | mov                 dword ptr [esi + 8], 0x6c694674
            //   c6460e00             | mov                 byte ptr [esi + 0xe], 0
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp

        $sequence_7 = { 56 e8???????? 83c40c c74614696d6520 c7064c6f6361 }
            // n = 5, score = 300
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   c74614696d6520       | mov                 dword ptr [esi + 0x14], 0x20656d69
            //   c7064c6f6361         | mov                 dword ptr [esi], 0x61636f4c

        $sequence_8 = { 034c2460 488b442450 894820 488b4c2450 }
            // n = 4, score = 100
            //   034c2460             | lea                 edx, dword ptr [esp + 0x40]
            //   488b442450           | dec                 eax
            //   894820               | mov                 ecx, dword ptr [esp + 0x70]
            //   488b4c2450           | add                 ecx, dword ptr [esp + 0x2c]

        $sequence_9 = { 0344242c 8bc8 e8???????? 4889442448 }
            // n = 4, score = 100
            //   0344242c             | add                 eax, dword ptr [esp + 0x2c]
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   4889442448           | dec                 eax

        $sequence_10 = { 03c1 89442434 8b442430 39442434 }
            // n = 4, score = 100
            //   03c1                 | mov                 dword ptr [esp + 0x20], eax
            //   89442434             | mov                 eax, dword ptr [esp + 0x20]
            //   8b442430             | add                 eax, 0xa
            //   39442434             | add                 eax, ecx

        $sequence_11 = { 03c1 89442420 8b542438 486bd218 }
            // n = 4, score = 100
            //   03c1                 | movzx               eax, byte ptr [eax + eax]
            //   89442420             | mov                 byte ptr [ecx + edx], al
            //   8b542438             | mov                 eax, dword ptr [esp + 0x18]
            //   486bd218             | add                 eax, ecx

        $sequence_12 = { 03c1 89442420 8b4c2438 488b442450 }
            // n = 4, score = 100
            //   03c1                 | dec                 eax
            //   89442420             | mov                 eax, dword ptr [esp + 0x38]
            //   8b4c2438             | inc                 edx
            //   488b442450           | movzx               eax, byte ptr [eax + eax]

        $sequence_13 = { 03c1 4863d0 488b4c2430 488b442438 }
            // n = 4, score = 100
            //   03c1                 | add                 ecx, dword ptr [esp + 0x60]
            //   4863d0               | dec                 eax
            //   488b4c2430           | mov                 eax, dword ptr [esp + 0x50]
            //   488b442438           | mov                 dword ptr [eax + 0x20], ecx

        $sequence_14 = { 034c242c 488b442470 894820 488d542440 }
            // n = 4, score = 100
            //   034c242c             | add                 eax, dword ptr [esp + 0x2c]
            //   488b442470           | mov                 ecx, eax
            //   894820               | dec                 eax
            //   488d542440           | mov                 dword ptr [esp + 0x48], eax

        $sequence_15 = { 03c1 89442420 8b442420 83c001 }
            // n = 4, score = 100
            //   03c1                 | add                 ecx, dword ptr [esp + 0x60]
            //   89442420             | dec                 eax
            //   8b442420             | mov                 eax, dword ptr [esp + 0x50]
            //   83c001               | mov                 dword ptr [eax + 0x20], ecx

    condition:
        7 of them and filesize < 402432
}