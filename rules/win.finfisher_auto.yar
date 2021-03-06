rule win_finfisher_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.finfisher."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.finfisher"
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
        $sequence_0 = { 68???????? 6804010000 8d85ccf9ffff 50 }
            // n = 4, score = 200
            //   68????????           |                     
            //   6804010000           | push                0x104
            //   8d85ccf9ffff         | lea                 eax, [ebp - 0x634]
            //   50                   | push                eax

        $sequence_1 = { 56 8d85d4fbffff 50 e8???????? }
            // n = 4, score = 200
            //   56                   | push                esi
            //   8d85d4fbffff         | lea                 eax, [ebp - 0x42c]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_2 = { 57 56 8d85ccf9ffff 50 }
            // n = 4, score = 200
            //   57                   | push                edi
            //   56                   | push                esi
            //   8d85ccf9ffff         | lea                 eax, [ebp - 0x634]
            //   50                   | push                eax

        $sequence_3 = { 6a04 5f 8b85b4f7ffff 397804 740a bb230000c0 e9???????? }
            // n = 7, score = 100
            //   6a04                 | push                4
            //   5f                   | pop                 edi
            //   8b85b4f7ffff         | mov                 eax, dword ptr [ebp - 0x84c]
            //   397804               | cmp                 dword ptr [eax + 4], edi
            //   740a                 | je                  0xc
            //   bb230000c0           | mov                 ebx, 0xc0000023
            //   e9????????           |                     

        $sequence_4 = { 011a 8b55f0 83450802 49 }
            // n = 4, score = 100
            //   011a                 | add                 dword ptr [edx], ebx
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   83450802             | add                 dword ptr [ebp + 8], 2
            //   49                   | dec                 ecx

        $sequence_5 = { 8b8590f7ffff 66c7005c00 8d85c0f7ffff 50 }
            // n = 4, score = 100
            //   8b8590f7ffff         | mov                 eax, dword ptr [ebp - 0x870]
            //   66c7005c00           | mov                 word ptr [eax], 0x5c
            //   8d85c0f7ffff         | lea                 eax, [ebp - 0x840]
            //   50                   | push                eax

        $sequence_6 = { eb06 ff15???????? c745fcfeffffff 56 56 56 }
            // n = 6, score = 100
            //   eb06                 | jmp                 8
            //   ff15????????         |                     
            //   c745fcfeffffff       | mov                 dword ptr [ebp - 4], 0xfffffffe
            //   56                   | push                esi
            //   56                   | push                esi
            //   56                   | push                esi

        $sequence_7 = { 0118 8b45f0 83450802 4f }
            // n = 4, score = 100
            //   0118                 | add                 dword ptr [eax], ebx
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   83450802             | add                 dword ptr [ebp + 8], 2
            //   4f                   | dec                 edi

        $sequence_8 = { 50 ff15???????? 83c410 8d85ccf9ffff 50 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c410               | add                 esp, 0x10
            //   8d85ccf9ffff         | lea                 eax, [ebp - 0x634]
            //   50                   | push                eax

        $sequence_9 = { 0145d8 ebcc 8975e4 eb07 }
            // n = 4, score = 100
            //   0145d8               | add                 dword ptr [ebp - 0x28], eax
            //   ebcc                 | jmp                 0xffffffce
            //   8975e4               | mov                 dword ptr [ebp - 0x1c], esi
            //   eb07                 | jmp                 9

        $sequence_10 = { 0108 83500400 a1???????? 8380780300003c 83fbfd }
            // n = 5, score = 100
            //   0108                 | add                 dword ptr [eax], ecx
            //   83500400             | adc                 dword ptr [eax + 4], 0
            //   a1????????           |                     
            //   8380780300003c       | add                 dword ptr [eax + 0x378], 0x3c
            //   83fbfd               | cmp                 ebx, -3

        $sequence_11 = { 0145d4 ebce 8975e4 eb07 }
            // n = 4, score = 100
            //   0145d4               | add                 dword ptr [ebp - 0x2c], eax
            //   ebce                 | jmp                 0xffffffd0
            //   8975e4               | mov                 dword ptr [ebp - 0x1c], esi
            //   eb07                 | jmp                 9

        $sequence_12 = { 6878563412 be00100000 56 6a01 ff15???????? b101 8bd8 }
            // n = 7, score = 100
            //   6878563412           | push                0x12345678
            //   be00100000           | mov                 esi, 0x1000
            //   56                   | push                esi
            //   6a01                 | push                1
            //   ff15????????         |                     
            //   b101                 | mov                 cl, 1
            //   8bd8                 | mov                 ebx, eax

    condition:
        7 of them and filesize < 262144
}