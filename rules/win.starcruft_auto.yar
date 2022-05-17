rule win_starcruft_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.starcruft."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.starcruft"
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
        $sequence_0 = { 8b08 83c108 51 e8???????? 83c40c 6a00 8d55f0 }
            // n = 7, score = 100
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   83c108               | add                 ecx, 8
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a00                 | push                0
            //   8d55f0               | lea                 edx, [ebp - 0x10]

        $sequence_1 = { 837dfcff 7502 eb6b c785d0fdffff24020000 8d85d0fdffff 50 8b4dfc }
            // n = 7, score = 100
            //   837dfcff             | cmp                 dword ptr [ebp - 4], -1
            //   7502                 | jne                 4
            //   eb6b                 | jmp                 0x6d
            //   c785d0fdffff24020000     | mov    dword ptr [ebp - 0x230], 0x224
            //   8d85d0fdffff         | lea                 eax, [ebp - 0x230]
            //   50                   | push                eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_2 = { 8b4508 50 ff15???????? 83c001 50 8b4d08 }
            // n = 6, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c001               | add                 eax, 1
            //   50                   | push                eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]

        $sequence_3 = { 8945fc 8d45e0 50 ff15???????? 8b0d???????? 0fb75108 52 }
            // n = 7, score = 100
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b0d????????         |                     
            //   0fb75108             | movzx               edx, word ptr [ecx + 8]
            //   52                   | push                edx

        $sequence_4 = { 8b4df4 c1e104 8b55f4 c1ea1c 0bca 034dfc 894df4 }
            // n = 7, score = 100
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   c1e104               | shl                 ecx, 4
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   c1ea1c               | shr                 edx, 0x1c
            //   0bca                 | or                  ecx, edx
            //   034dfc               | add                 ecx, dword ptr [ebp - 4]
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx

        $sequence_5 = { ff15???????? 8b8da8fdffff 51 e8???????? 83c404 b801000000 8b4df8 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8b8da8fdffff         | mov                 ecx, dword ptr [ebp - 0x258]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   b801000000           | mov                 eax, 1
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]

        $sequence_6 = { c7000c000000 8b4d0c 8b11 52 e8???????? 83c404 }
            // n = 6, score = 100
            //   c7000c000000         | mov                 dword ptr [eax], 0xc
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_7 = { 334dfc 234df0 334dfc 034db8 8b55f8 8d840adb702024 8945f8 }
            // n = 7, score = 100
            //   334dfc               | xor                 ecx, dword ptr [ebp - 4]
            //   234df0               | and                 ecx, dword ptr [ebp - 0x10]
            //   334dfc               | xor                 ecx, dword ptr [ebp - 4]
            //   034db8               | add                 ecx, dword ptr [ebp - 0x48]
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   8d840adb702024       | lea                 eax, [edx + ecx + 0x242070db]
            //   8945f8               | mov                 dword ptr [ebp - 8], eax

        $sequence_8 = { 51 ff15???????? 8d95a0edffff 52 8d85b0f2ffff 50 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8d95a0edffff         | lea                 edx, [ebp - 0x1260]
            //   52                   | push                edx
            //   8d85b0f2ffff         | lea                 eax, [ebp - 0xd50]
            //   50                   | push                eax

        $sequence_9 = { 894df8 8b55f8 0fb702 85c0 7415 8b4df8 0fb711 }
            // n = 7, score = 100
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   0fb702               | movzx               eax, word ptr [edx]
            //   85c0                 | test                eax, eax
            //   7415                 | je                  0x17
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   0fb711               | movzx               edx, word ptr [ecx]

    condition:
        7 of them and filesize < 294912
}