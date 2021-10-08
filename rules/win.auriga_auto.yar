rule win_auriga_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.auriga."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.auriga"
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
        $sequence_0 = { 6bc014 e9???????? 3d02010000 0f8594000000 8b461c }
            // n = 5, score = 100
            //   6bc014               | imul                eax, eax, 0x14
            //   e9????????           |                     
            //   3d02010000           | cmp                 eax, 0x102
            //   0f8594000000         | jne                 0x9a
            //   8b461c               | mov                 eax, dword ptr [esi + 0x1c]

        $sequence_1 = { e8???????? c9 c20c00 ffb508fcffff 8b8504fcffff 8d8405fcfbffff 50 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   c9                   | leave               
            //   c20c00               | ret                 0xc
            //   ffb508fcffff         | push                dword ptr [ebp - 0x3f8]
            //   8b8504fcffff         | mov                 eax, dword ptr [ebp - 0x3fc]
            //   8d8405fcfbffff       | lea                 eax, dword ptr [ebp + eax - 0x404]
            //   50                   | push                eax

        $sequence_2 = { 8325????????00 8325????????00 803d????????00 56 57 }
            // n = 5, score = 100
            //   8325????????00       |                     
            //   8325????????00       |                     
            //   803d????????00       |                     
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_3 = { b8010000c0 eb70 ff15???????? 833d????????00 a3???????? 74e5 }
            // n = 6, score = 100
            //   b8010000c0           | mov                 eax, 0xc0000001
            //   eb70                 | jmp                 0x72
            //   ff15????????         |                     
            //   833d????????00       |                     
            //   a3????????           |                     
            //   74e5                 | je                  0xffffffe7

        $sequence_4 = { ff15???????? 3bc7 0f8ce7010000 8d85e8f9ffff 50 8d85e0f9ffff 50 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   3bc7                 | cmp                 eax, edi
            //   0f8ce7010000         | jl                  0x1ed
            //   8d85e8f9ffff         | lea                 eax, dword ptr [ebp - 0x618]
            //   50                   | push                eax
            //   8d85e0f9ffff         | lea                 eax, dword ptr [ebp - 0x620]
            //   50                   | push                eax

        $sequence_5 = { 6a00 6a00 50 ff15???????? 8bf8 85ff 7c0b }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi
            //   7c0b                 | jl                  0xd

        $sequence_6 = { 85c0 53 75e1 6888130000 50 b800ca9a3b }
            // n = 6, score = 100
            //   85c0                 | test                eax, eax
            //   53                   | push                ebx
            //   75e1                 | jne                 0xffffffe3
            //   6888130000           | push                0x1388
            //   50                   | push                eax
            //   b800ca9a3b           | mov                 eax, 0x3b9aca00

        $sequence_7 = { 3d09010000 740b 3d10010000 0f85f4000000 8b461c bba8000000 33d2 }
            // n = 7, score = 100
            //   3d09010000           | cmp                 eax, 0x109
            //   740b                 | je                  0xd
            //   3d10010000           | cmp                 eax, 0x110
            //   0f85f4000000         | jne                 0xfa
            //   8b461c               | mov                 eax, dword ptr [esi + 0x1c]
            //   bba8000000           | mov                 ebx, 0xa8
            //   33d2                 | xor                 edx, edx

        $sequence_8 = { 668b5912 668959fe 668b591a 66895906 8bca 75c6 }
            // n = 6, score = 100
            //   668b5912             | mov                 bx, word ptr [ecx + 0x12]
            //   668959fe             | mov                 word ptr [ecx - 2], bx
            //   668b591a             | mov                 bx, word ptr [ecx + 0x1a]
            //   66895906             | mov                 word ptr [ecx + 6], bx
            //   8bca                 | mov                 ecx, edx
            //   75c6                 | jne                 0xffffffc8

        $sequence_9 = { 740b 6a00 ff7508 ff15???????? 8b4514 6a00 6a00 }
            // n = 7, score = 100
            //   740b                 | je                  0xd
            //   6a00                 | push                0
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   6a00                 | push                0
            //   6a00                 | push                0

    condition:
        7 of them and filesize < 75776
}