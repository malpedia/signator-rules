rule win_fakerean_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.fakerean."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fakerean"
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
        $sequence_0 = { 50 6a0e 8d4dfc e8???????? 59 59 6a00 }
            // n = 7, score = 300
            //   50                   | push                eax
            //   6a0e                 | push                0xe
            //   8d4dfc               | lea                 ecx, [ebp - 4]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   6a00                 | push                0

        $sequence_1 = { 85c0 7421 8b35???????? ff45f8 8b45f8 81c300080000 3b8600280000 }
            // n = 7, score = 300
            //   85c0                 | test                eax, eax
            //   7421                 | je                  0x23
            //   8b35????????         |                     
            //   ff45f8               | inc                 dword ptr [ebp - 8]
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   81c300080000         | add                 ebx, 0x800
            //   3b8600280000         | cmp                 eax, dword ptr [esi + 0x2800]

        $sequence_2 = { ff750c ff7508 ff15???????? 85c0 7811 ff7510 ff750c }
            // n = 7, score = 300
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7811                 | js                  0x13
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff750c               | push                dword ptr [ebp + 0xc]

        $sequence_3 = { e8???????? 83c40c ff75f4 ff15???????? 8d45f0 50 33ff }
            // n = 7, score = 300
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   ff15????????         |                     
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax
            //   33ff                 | xor                 edi, edi

        $sequence_4 = { 66890459 8b45f4 6a03 99 }
            // n = 4, score = 300
            //   66890459             | mov                 word ptr [ecx + ebx*2], ax
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   6a03                 | push                3
            //   99                   | cdq                 

        $sequence_5 = { 56 ff15???????? 85c0 7503 6a02 5f 8bc7 }
            // n = 7, score = 300
            //   56                   | push                esi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7503                 | jne                 5
            //   6a02                 | push                2
            //   5f                   | pop                 edi
            //   8bc7                 | mov                 eax, edi

        $sequence_6 = { 83fe20 750c 3983f0030000 7595 6a22 eb90 }
            // n = 6, score = 300
            //   83fe20               | cmp                 esi, 0x20
            //   750c                 | jne                 0xe
            //   3983f0030000         | cmp                 dword ptr [ebx + 0x3f0], eax
            //   7595                 | jne                 0xffffff97
            //   6a22                 | push                0x22
            //   eb90                 | jmp                 0xffffff92

        $sequence_7 = { e9???????? 81fee1690000 752a 391d???????? 750b 6a01 6a02 }
            // n = 7, score = 300
            //   e9????????           |                     
            //   81fee1690000         | cmp                 esi, 0x69e1
            //   752a                 | jne                 0x2c
            //   391d????????         |                     
            //   750b                 | jne                 0xd
            //   6a01                 | push                1
            //   6a02                 | push                2

        $sequence_8 = { 8b5d0c 56 33f6 663935???????? 7407 b8???????? eb08 }
            // n = 7, score = 300
            //   8b5d0c               | mov                 ebx, dword ptr [ebp + 0xc]
            //   56                   | push                esi
            //   33f6                 | xor                 esi, esi
            //   663935????????       |                     
            //   7407                 | je                  9
            //   b8????????           |                     
            //   eb08                 | jmp                 0xa

        $sequence_9 = { 2b4df0 3bc8 7c13 397dfc 750b 6a01 6a01 }
            // n = 7, score = 300
            //   2b4df0               | sub                 ecx, dword ptr [ebp - 0x10]
            //   3bc8                 | cmp                 ecx, eax
            //   7c13                 | jl                  0x15
            //   397dfc               | cmp                 dword ptr [ebp - 4], edi
            //   750b                 | jne                 0xd
            //   6a01                 | push                1
            //   6a01                 | push                1

    condition:
        7 of them and filesize < 4071424
}