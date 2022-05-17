rule win_goldenspy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.goldenspy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.goldenspy"
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
        $sequence_0 = { 8b4704 b9???????? 0f1f00 8a10 3a11 751a }
            // n = 6, score = 100
            //   8b4704               | mov                 eax, dword ptr [edi + 4]
            //   b9????????           |                     
            //   0f1f00               | nop                 dword ptr [eax]
            //   8a10                 | mov                 dl, byte ptr [eax]
            //   3a11                 | cmp                 dl, byte ptr [ecx]
            //   751a                 | jne                 0x1c

        $sequence_1 = { 7404 8b10 eb02 33d2 8b4a08 8b45c4 49 }
            // n = 7, score = 100
            //   7404                 | je                  6
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   eb02                 | jmp                 4
            //   33d2                 | xor                 edx, edx
            //   8b4a08               | mov                 ecx, dword ptr [edx + 8]
            //   8b45c4               | mov                 eax, dword ptr [ebp - 0x3c]
            //   49                   | dec                 ecx

        $sequence_2 = { 8d4de4 6a01 8945e4 e8???????? c745fc00000000 ff75e4 e8???????? }
            // n = 7, score = 100
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]
            //   6a01                 | push                1
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   e8????????           |                     
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   ff75e4               | push                dword ptr [ebp - 0x1c]
            //   e8????????           |                     

        $sequence_3 = { 8945d0 756e c745e400000000 c745e80f000000 c645d400 3bc6 740c }
            // n = 7, score = 100
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax
            //   756e                 | jne                 0x70
            //   c745e400000000       | mov                 dword ptr [ebp - 0x1c], 0
            //   c745e80f000000       | mov                 dword ptr [ebp - 0x18], 0xf
            //   c645d400             | mov                 byte ptr [ebp - 0x2c], 0
            //   3bc6                 | cmp                 eax, esi
            //   740c                 | je                  0xe

        $sequence_4 = { c645fc00 e8???????? 8b55e8 8bf0 85f6 7431 83fa10 }
            // n = 7, score = 100
            //   c645fc00             | mov                 byte ptr [ebp - 4], 0
            //   e8????????           |                     
            //   8b55e8               | mov                 edx, dword ptr [ebp - 0x18]
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   7431                 | je                  0x33
            //   83fa10               | cmp                 edx, 0x10

        $sequence_5 = { 8b4e10 894dc8 8b4608 0f4555e8 8955e8 80780d00 }
            // n = 6, score = 100
            //   8b4e10               | mov                 ecx, dword ptr [esi + 0x10]
            //   894dc8               | mov                 dword ptr [ebp - 0x38], ecx
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   0f4555e8             | cmovne              edx, dword ptr [ebp - 0x18]
            //   8955e8               | mov                 dword ptr [ebp - 0x18], edx
            //   80780d00             | cmp                 byte ptr [eax + 0xd], 0

        $sequence_6 = { 53 51 c645b800 8bcf ff75b8 53 e8???????? }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   51                   | push                ecx
            //   c645b800             | mov                 byte ptr [ebp - 0x48], 0
            //   8bcf                 | mov                 ecx, edi
            //   ff75b8               | push                dword ptr [ebp - 0x48]
            //   53                   | push                ebx
            //   e8????????           |                     

        $sequence_7 = { 807ddc00 74df 8b75e0 85f6 741c 8b06 }
            // n = 6, score = 100
            //   807ddc00             | cmp                 byte ptr [ebp - 0x24], 0
            //   74df                 | je                  0xffffffe1
            //   8b75e0               | mov                 esi, dword ptr [ebp - 0x20]
            //   85f6                 | test                esi, esi
            //   741c                 | je                  0x1e
            //   8b06                 | mov                 eax, dword ptr [esi]

        $sequence_8 = { 83f81f 0f87a6000000 52 51 e8???????? 83c408 8ac3 }
            // n = 7, score = 100
            //   83f81f               | cmp                 eax, 0x1f
            //   0f87a6000000         | ja                  0xac
            //   52                   | push                edx
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8ac3                 | mov                 al, bl

        $sequence_9 = { 50 e8???????? 8d041e 33d2 83c40c 33c9 3bf0 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d041e               | lea                 eax, [esi + ebx]
            //   33d2                 | xor                 edx, edx
            //   83c40c               | add                 esp, 0xc
            //   33c9                 | xor                 ecx, ecx
            //   3bf0                 | cmp                 esi, eax

    condition:
        7 of them and filesize < 1081344
}