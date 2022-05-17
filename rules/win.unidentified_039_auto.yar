rule win_unidentified_039_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.unidentified_039."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_039"
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
        $sequence_0 = { ff75f8 ff15???????? c745e4c82c0000 c745f0071c0000 c745f406730000 }
            // n = 5, score = 100
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff15????????         |                     
            //   c745e4c82c0000       | mov                 dword ptr [ebp - 0x1c], 0x2cc8
            //   c745f0071c0000       | mov                 dword ptr [ebp - 0x10], 0x1c07
            //   c745f406730000       | mov                 dword ptr [ebp - 0xc], 0x7306

        $sequence_1 = { 83b89000000000 7e0c e8???????? 0590000000 ff08 c3 55 }
            // n = 7, score = 100
            //   83b89000000000       | cmp                 dword ptr [eax + 0x90], 0
            //   7e0c                 | jle                 0xe
            //   e8????????           |                     
            //   0590000000           | add                 eax, 0x90
            //   ff08                 | dec                 dword ptr [eax]
            //   c3                   | ret                 
            //   55                   | push                ebp

        $sequence_2 = { c745d8b65a0000 8b45f4 8b4df0 2bc8 034dd0 034dd4 8b45d8 }
            // n = 7, score = 100
            //   c745d8b65a0000       | mov                 dword ptr [ebp - 0x28], 0x5ab6
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   2bc8                 | sub                 ecx, eax
            //   034dd0               | add                 ecx, dword ptr [ebp - 0x30]
            //   034dd4               | add                 ecx, dword ptr [ebp - 0x2c]
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]

        $sequence_3 = { 8b4dec 3bc8 7c0a 53 ff15???????? }
            // n = 5, score = 100
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   3bc8                 | cmp                 ecx, eax
            //   7c0a                 | jl                  0xc
            //   53                   | push                ebx
            //   ff15????????         |                     

        $sequence_4 = { 8bc6 5e c20400 a1???????? 83f8ff 56 8b35???????? }
            // n = 7, score = 100
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   c20400               | ret                 4
            //   a1????????           |                     
            //   83f8ff               | cmp                 eax, -1
            //   56                   | push                esi
            //   8b35????????         |                     

        $sequence_5 = { c745cc232e0000 c745d0ae4f0000 8b45ec 8b4de8 2bc8 8b45cc 2bc8 }
            // n = 7, score = 100
            //   c745cc232e0000       | mov                 dword ptr [ebp - 0x34], 0x2e23
            //   c745d0ae4f0000       | mov                 dword ptr [ebp - 0x30], 0x4fae
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   2bc8                 | sub                 ecx, eax
            //   8b45cc               | mov                 eax, dword ptr [ebp - 0x34]
            //   2bc8                 | sub                 ecx, eax

        $sequence_6 = { 8d4500 50 e8???????? 59 8d4dc8 8ad8 e8???????? }
            // n = 7, score = 100
            //   8d4500               | lea                 eax, [ebp]
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8d4dc8               | lea                 ecx, [ebp - 0x38]
            //   8ad8                 | mov                 bl, al
            //   e8????????           |                     

        $sequence_7 = { 47 47 81fe???????? 0f8c37ffffff 668325????????00 5f 5e }
            // n = 7, score = 100
            //   47                   | inc                 edi
            //   47                   | inc                 edi
            //   81fe????????         |                     
            //   0f8c37ffffff         | jl                  0xffffff3d
            //   668325????????00     |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_8 = { c745d8e5190000 c745e0037e0000 83c0dd c745dcca4a0000 8945d4 8b45d8 8b4dec }
            // n = 7, score = 100
            //   c745d8e5190000       | mov                 dword ptr [ebp - 0x28], 0x19e5
            //   c745e0037e0000       | mov                 dword ptr [ebp - 0x20], 0x7e03
            //   83c0dd               | add                 eax, -0x23
            //   c745dcca4a0000       | mov                 dword ptr [ebp - 0x24], 0x4aca
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]

        $sequence_9 = { c7459090300000 c74584d61b0000 8b459c 03458c 034588 8b4d84 33c1 }
            // n = 7, score = 100
            //   c7459090300000       | mov                 dword ptr [ebp - 0x70], 0x3090
            //   c74584d61b0000       | mov                 dword ptr [ebp - 0x7c], 0x1bd6
            //   8b459c               | mov                 eax, dword ptr [ebp - 0x64]
            //   03458c               | add                 eax, dword ptr [ebp - 0x74]
            //   034588               | add                 eax, dword ptr [ebp - 0x78]
            //   8b4d84               | mov                 ecx, dword ptr [ebp - 0x7c]
            //   33c1                 | xor                 eax, ecx

    condition:
        7 of them and filesize < 262144
}