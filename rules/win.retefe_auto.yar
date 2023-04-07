rule win_retefe_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.retefe."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.retefe"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
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
        $sequence_0 = { 6a00 6a01 ff15???????? 8bf0 85f6 7410 6a09 }
            // n = 7, score = 1200
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   7410                 | je                  0x12
            //   6a09                 | push                9

        $sequence_1 = { 51 8bf8 ffd6 85c0 }
            // n = 4, score = 1200
            //   51                   | push                ecx
            //   8bf8                 | mov                 edi, eax
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax

        $sequence_2 = { 68f5000000 50 ff15???????? b801000000 }
            // n = 4, score = 1200
            //   68f5000000           | push                0xf5
            //   50                   | push                eax
            //   ff15????????         |                     
            //   b801000000           | mov                 eax, 1

        $sequence_3 = { 8b4e04 33c0 83c404 394104 }
            // n = 4, score = 800
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   33c0                 | xor                 eax, eax
            //   83c404               | add                 esp, 4
            //   394104               | cmp                 dword ptr [ecx + 4], eax

        $sequence_4 = { 6a16 89442470 e8???????? 83c45c 50 57 }
            // n = 6, score = 800
            //   6a16                 | push                0x16
            //   89442470             | mov                 dword ptr [esp + 0x70], eax
            //   e8????????           |                     
            //   83c45c               | add                 esp, 0x5c
            //   50                   | push                eax
            //   57                   | push                edi

        $sequence_5 = { e8???????? 6a08 e8???????? 894604 83c404 8bc6 e8???????? }
            // n = 7, score = 800
            //   e8????????           |                     
            //   6a08                 | push                8
            //   e8????????           |                     
            //   894604               | mov                 dword ptr [esi + 4], eax
            //   83c404               | add                 esp, 4
            //   8bc6                 | mov                 eax, esi
            //   e8????????           |                     

        $sequence_6 = { 6ac5 6ad6 6ac9 6a4f 6ad3 6add }
            // n = 6, score = 800
            //   6ac5                 | push                -0x3b
            //   6ad6                 | push                -0x2a
            //   6ac9                 | push                -0x37
            //   6a4f                 | push                0x4f
            //   6ad3                 | push                -0x2d
            //   6add                 | push                -0x23

        $sequence_7 = { 880c10 8b4e04 40 3b4104 }
            // n = 4, score = 800
            //   880c10               | mov                 byte ptr [eax + edx], cl
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   40                   | inc                 eax
            //   3b4104               | cmp                 eax, dword ptr [ecx + 4]

        $sequence_8 = { 6a48 6a80 6a18 6ace 6a5e }
            // n = 5, score = 800
            //   6a48                 | push                0x48
            //   6a80                 | push                -0x80
            //   6a18                 | push                0x18
            //   6ace                 | push                -0x32
            //   6a5e                 | push                0x5e

        $sequence_9 = { 52 e8???????? 8b4e04 8901 }
            // n = 4, score = 800
            //   52                   | push                edx
            //   e8????????           |                     
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   8901                 | mov                 dword ptr [ecx], eax

        $sequence_10 = { 6ab3 6a0b 6ada 6a07 e8???????? 83c420 }
            // n = 6, score = 800
            //   6ab3                 | push                -0x4d
            //   6a0b                 | push                0xb
            //   6ada                 | push                -0x26
            //   6a07                 | push                7
            //   e8????????           |                     
            //   83c420               | add                 esp, 0x20

        $sequence_11 = { 8b4e04 8901 8b4e04 33c0 }
            // n = 4, score = 800
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   33c0                 | xor                 eax, eax

        $sequence_12 = { 6a3b 6afd 6ada 6a44 6a61 6ac2 }
            // n = 6, score = 800
            //   6a3b                 | push                0x3b
            //   6afd                 | push                -3
            //   6ada                 | push                -0x26
            //   6a44                 | push                0x44
            //   6a61                 | push                0x61
            //   6ac2                 | push                -0x3e

        $sequence_13 = { 6bc930 53 8b5d10 8b0485a0bf4200 56 8b7508 57 }
            // n = 7, score = 100
            //   6bc930               | imul                ecx, ecx, 0x30
            //   53                   | push                ebx
            //   8b5d10               | mov                 ebx, dword ptr [ebp + 0x10]
            //   8b0485a0bf4200       | mov                 eax, dword ptr [eax*4 + 0x42bfa0]
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   57                   | push                edi

        $sequence_14 = { 8b7508 83c8ff 8d4e04 f00fc101 7530 85f6 7425 }
            // n = 7, score = 100
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   83c8ff               | or                  eax, 0xffffffff
            //   8d4e04               | lea                 ecx, [esi + 4]
            //   f00fc101             | lock xadd           dword ptr [ecx], eax
            //   7530                 | jne                 0x32
            //   85f6                 | test                esi, esi
            //   7425                 | je                  0x27

        $sequence_15 = { 50 8b08 ff511c 33c0 5f }
            // n = 5, score = 100
            //   50                   | push                eax
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff511c               | call                dword ptr [ecx + 0x1c]
            //   33c0                 | xor                 eax, eax
            //   5f                   | pop                 edi

        $sequence_16 = { ff15???????? 33c0 5e c3 b805400080 }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   b805400080           | mov                 eax, 0x80004005

        $sequence_17 = { 8365c800 c745cced4d4000 a1???????? 8d4dc8 33c1 }
            // n = 5, score = 100
            //   8365c800             | and                 dword ptr [ebp - 0x38], 0
            //   c745cced4d4000       | mov                 dword ptr [ebp - 0x34], 0x404ded
            //   a1????????           |                     
            //   8d4dc8               | lea                 ecx, [ebp - 0x38]
            //   33c1                 | xor                 eax, ecx

        $sequence_18 = { 2bf7 8bc6 99 0305???????? }
            // n = 4, score = 100
            //   2bf7                 | sub                 esi, edi
            //   8bc6                 | mov                 eax, esi
            //   99                   | cdq                 
            //   0305????????         |                     

        $sequence_19 = { 50 e8???????? 0fb7d8 8d44244c }
            // n = 4, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   0fb7d8               | movzx               ebx, ax
            //   8d44244c             | lea                 eax, [esp + 0x4c]

        $sequence_20 = { c1f906 53 6bd830 56 8b048da0bf4200 57 }
            // n = 6, score = 100
            //   c1f906               | sar                 ecx, 6
            //   53                   | push                ebx
            //   6bd830               | imul                ebx, eax, 0x30
            //   56                   | push                esi
            //   8b048da0bf4200       | mov                 eax, dword ptr [ecx*4 + 0x42bfa0]
            //   57                   | push                edi

        $sequence_21 = { 6685c9 743e 6a20 8bce }
            // n = 4, score = 100
            //   6685c9               | test                cx, cx
            //   743e                 | je                  0x40
            //   6a20                 | push                0x20
            //   8bce                 | mov                 ecx, esi

        $sequence_22 = { 8b8c2410200000 8bc1 53 8b9c240c200000 }
            // n = 4, score = 100
            //   8b8c2410200000       | mov                 ecx, dword ptr [esp + 0x2010]
            //   8bc1                 | mov                 eax, ecx
            //   53                   | push                ebx
            //   8b9c240c200000       | mov                 ebx, dword ptr [esp + 0x200c]

        $sequence_23 = { 750a c7872010000001000000 33c0 83fdff 884712 }
            // n = 5, score = 100
            //   750a                 | jne                 0xc
            //   c7872010000001000000     | mov    dword ptr [edi + 0x1020], 1
            //   33c0                 | xor                 eax, eax
            //   83fdff               | cmp                 ebp, -1
            //   884712               | mov                 byte ptr [edi + 0x12], al

        $sequence_24 = { 56 ff15???????? 6800000100 55 }
            // n = 4, score = 100
            //   56                   | push                esi
            //   ff15????????         |                     
            //   6800000100           | push                0x10000
            //   55                   | push                ebp

        $sequence_25 = { 85c0 7414 c70000000000 f6c102 7409 b82b800280 }
            // n = 6, score = 100
            //   85c0                 | test                eax, eax
            //   7414                 | je                  0x16
            //   c70000000000         | mov                 dword ptr [eax], 0
            //   f6c102               | test                cl, 2
            //   7409                 | je                  0xb
            //   b82b800280           | mov                 eax, 0x8002802b

        $sequence_26 = { 85c0 740b 8bcb e8???????? 8365fc00 }
            // n = 5, score = 100
            //   85c0                 | test                eax, eax
            //   740b                 | je                  0xd
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   8365fc00             | and                 dword ptr [ebp - 4], 0

        $sequence_27 = { e8???????? 8b442438 85ed 7411 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   8b442438             | mov                 eax, dword ptr [esp + 0x38]
            //   85ed                 | test                ebp, ebp
            //   7411                 | je                  0x13

        $sequence_28 = { ff5008 6a14 56 e8???????? 83c408 33c0 }
            // n = 6, score = 100
            //   ff5008               | call                dword ptr [eax + 8]
            //   6a14                 | push                0x14
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   33c0                 | xor                 eax, eax

    condition:
        7 of them and filesize < 843776
}