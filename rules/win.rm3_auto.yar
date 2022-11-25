rule win_rm3_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.rm3."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rm3"
        malpedia_rule_date = "20221118"
        malpedia_hash = "e0702e2e6d1d00da65c8a29a4ebacd0a4c59e1af"
        malpedia_version = "20221125"
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
        $sequence_0 = { 8d5410ff 48 f7d0 23d0 8b460c 03c2 }
            // n = 6, score = 2300
            //   8d5410ff             | mov                 eax, dword ptr [esi + 8]
            //   48                   | mov                 edx, dword ptr [ecx + 0x3c]
            //   f7d0                 | mov                 ebx, dword ptr [esi + 0x10]
            //   23d0                 | lea                 eax, [eax + edi - 1]
            //   8b460c               | dec                 edi
            //   03c2                 | not                 edi

        $sequence_1 = { 7303 8975f8 8b45f8 83c628 ff4dfc 85c0 }
            // n = 6, score = 2300
            //   7303                 | mov                 esi, ecx
            //   8975f8               | cmp                 esi, eax
            //   8b45f8               | dec                 esp
            //   83c628               | mov                 ebp, edx
            //   ff4dfc               | xor                 edx, edx
            //   85c0                 | dec                 eax

        $sequence_2 = { 23fa 3bf8 7609 8b413c 8d5418ff eb0a 8b4138 }
            // n = 7, score = 2300
            //   23fa                 | mov                 dword ptr [edi + 8], ebx
            //   3bf8                 | xor                 esi, esi
            //   7609                 | jmp                 0x1a
            //   8b413c               | xor                 eax, eax
            //   8d5418ff             | test                eax, eax
            //   eb0a                 | je                  0xc
            //   8b4138               | dec                 eax

        $sequence_3 = { 8b4808 ff7004 034c240c 8b00 51 03c2 }
            // n = 6, score = 2300
            //   8b4808               | cmp                 edi, eax
            //   ff7004               | movzx               eax, word ptr [ecx + 0x14]
            //   034c240c             | push                esi
            //   8b00                 | push                edi
            //   51                   | lea                 esi, [eax + ecx + 0x18]
            //   03c2                 | mov                 eax, dword ptr [ebp + 8]

        $sequence_4 = { 51 51 8b483c 03c8 0fb74106 8365f800 }
            // n = 6, score = 2300
            //   51                   | xor                 eax, eax
            //   51                   | jae                 5
            //   8b483c               | mov                 dword ptr [ebp - 8], esi
            //   03c8                 | mov                 eax, dword ptr [ebp - 8]
            //   0fb74106             | add                 esi, 0x28
            //   8365f800             | dec                 dword ptr [ebp - 4]

        $sequence_5 = { 8d4438ff 4f f7d7 23c7 8d7c13ff 4a f7d2 }
            // n = 7, score = 2300
            //   8d4438ff             | test                eax, eax
            //   4f                   | and                 edi, edx
            //   f7d7                 | cmp                 edi, eax
            //   23c7                 | jbe                 0xd
            //   8d7c13ff             | mov                 eax, dword ptr [ecx + 0x3c]
            //   4a                   | lea                 edx, [eax + ebx - 1]
            //   f7d2                 | jmp                 0x17

        $sequence_6 = { 8b4608 8b513c 8b5e10 8d4438ff 4f f7d7 }
            // n = 6, score = 2300
            //   8b4608               | mov                 esi, edx
            //   8b513c               | inc                 ebp
            //   8b5e10               | xor                 ebp, ebp
            //   8d4438ff             | inc                 ebp
            //   4f                   | xor                 ecx, ecx
            //   f7d7                 | inc                 ebp

        $sequence_7 = { 57 8d740818 8b4508 3b460c 7247 8b7938 8b4608 }
            // n = 7, score = 2300
            //   57                   | mov                 eax, dword ptr [ecx + 0x38]
            //   8d740818             | mov                 eax, dword ptr [ebp - 8]
            //   8b4508               | add                 esi, 0x28
            //   3b460c               | dec                 dword ptr [ebp - 4]
            //   7247                 | test                eax, eax
            //   8b7938               | jne                 0xf
            //   8b4608               | cmp                 dword ptr [ebp - 4], eax

        $sequence_8 = { e8???????? 8b4d0c 57 8bc6 8d9558feffff }
            // n = 5, score = 1800
            //   e8????????           |                     
            //   8b4d0c               | and                 edi, edx
            //   57                   | mov                 eax, dword ptr [esi + 8]
            //   8bc6                 | mov                 edx, dword ptr [ecx + 0x3c]
            //   8d9558feffff         | mov                 ebx, dword ptr [esi + 0x10]

        $sequence_9 = { 8bc6 e8???????? 6a58 6a00 56 e8???????? }
            // n = 6, score = 1800
            //   8bc6                 | and                 eax, edi
            //   e8????????           |                     
            //   6a58                 | lea                 edi, [ebx + edx - 1]
            //   6a00                 | dec                 edx
            //   56                   | not                 edx
            //   e8????????           |                     

        $sequence_10 = { 83c6f8 33d2 f7f6 8bf2 83c608 56 }
            // n = 6, score = 1800
            //   83c6f8               | mov                 eax, esi
            //   33d2                 | push                0x58
            //   f7f6                 | push                0
            //   8bf2                 | push                esi
            //   83c608               | mov                 ecx, dword ptr [ebp + 0xc]
            //   56                   | push                edi

        $sequence_11 = { 8bf0 2b7508 f7de 1bf6 83e60b 750f 8b450c }
            // n = 7, score = 1800
            //   8bf0                 | lea                 eax, [eax + edi - 1]
            //   2b7508               | dec                 edi
            //   f7de                 | not                 edi
            //   1bf6                 | mov                 dword ptr [ecx], esi
            //   83e60b               | mov                 esi, dword ptr [eax + 4]
            //   750f                 | mov                 dword ptr [ecx + 4], esi
            //   8b450c               | mov                 ecx, dword ptr [eax + 8]

        $sequence_12 = { ff15???????? 6a01 ff750c 8d4d0c 51 }
            // n = 5, score = 1800
            //   ff15????????         |                     
            //   6a01                 | test                eax, eax
            //   ff750c               | jne                 0xc
            //   8d4d0c               | cmp                 dword ptr [ebp - 4], eax
            //   51                   | jne                 0xffffffab

        $sequence_13 = { 8d45fc 50 53 ffd7 85c0 740f }
            // n = 6, score = 1800
            //   8d45fc               | jne                 0x18
            //   50                   | mov                 eax, dword ptr [ebp + 0xc]
            //   53                   | mov                 ebx, eax
            //   ffd7                 | mov                 edi, ecx
            //   85c0                 | lea                 esi, [ebp - 0x110]
            //   740f                 | mov                 ecx, esi

        $sequence_14 = { 8bd8 8bf9 8db5f0feffff 8bce 8d041b 51 8945f8 }
            // n = 7, score = 1800
            //   8bd8                 | mov                 eax, dword ptr [eax]
            //   8bf9                 | push                ecx
            //   8db5f0feffff         | add                 eax, edx
            //   8bce                 | push                eax
            //   8d041b               | add                 esp, 0xc
            //   51                   | add                 esi, 0x28
            //   8945f8               | dec                 dword ptr [ebp - 4]

        $sequence_15 = { 6a01 ff7508 ffd6 8bf0 85f6 7c0f 6a1c }
            // n = 7, score = 1800
            //   6a01                 | mov                 eax, esi
            //   ff7508               | lea                 edx, [ebp - 0x1a8]
            //   ffd6                 | mov                 esi, eax
            //   8bf0                 | sub                 esi, dword ptr [ebp + 8]
            //   85f6                 | neg                 esi
            //   7c0f                 | sbb                 esi, esi
            //   6a1c                 | and                 esi, 0xb

        $sequence_16 = { eb60 83a424a800000000 e9???????? 8364242800 488d442460 4c8d8c24a8000000 }
            // n = 6, score = 300
            //   eb60                 | je                  0x6c
            //   83a424a800000000     | test                edi, edi
            //   e9????????           |                     
            //   8364242800           | dec                 eax
            //   488d442460           | mov                 ebx, eax
            //   4c8d8c24a8000000     | je                  0x67

        $sequence_17 = { b800100000 33db d1ee 458be0 458bf1 3bf0 4c8bea }
            // n = 7, score = 300
            //   b800100000           | mov                 al, byte ptr [esi]
            //   33db                 | cmp                 al, 0x30
            //   d1ee                 | jb                  6
            //   458be0               | mov                 ecx, 0xf704be7
            //   458bf1               | dec                 eax
            //   3bf0                 | test                eax, eax
            //   4c8bea               | je                  0x27

        $sequence_18 = { 754c 83c201 4883c001 83fa10 72ef 898c24a8000000 ff15???????? }
            // n = 7, score = 300
            //   754c                 | inc                 ebp
            //   83c201               | dec                 ecx
            //   4883c001             | mov                 ecx, eax
            //   83fa10               | dec                 eax
            //   72ef                 | shr                 ecx, 0x1b
            //   898c24a8000000       | dec                 ecx
            //   ff15????????         |                     

        $sequence_19 = { 4c33c0 48b81ddd6c4f91f44525 498bc8 48c1e91b 4933c8 480fafc8 0fb7c1 }
            // n = 7, score = 300
            //   4c33c0               | jmp                 4
            //   48b81ddd6c4f91f44525     | dec    esp
            //   498bc8               | xor                 eax, eax
            //   48c1e91b             | dec                 eax
            //   4933c8               | mov                 eax, 0x4f6cdd1d
            //   480fafc8             | xchg                eax, ecx
            //   0fb7c1               | hlt                 

        $sequence_20 = { 746a 85ff 488bd8 7460 8a06 3c30 7204 }
            // n = 7, score = 300
            //   746a                 | xor                 ecx, eax
            //   85ff                 | dec                 eax
            //   488bd8               | imul                ecx, eax
            //   7460                 | movzx               eax, cx
            //   8a06                 | jne                 0x4e
            //   3c30                 | add                 edx, 1
            //   7204                 | dec                 eax

        $sequence_21 = { 33d2 ff15???????? 48895f08 33f6 eb12 488b0d???????? }
            // n = 6, score = 300
            //   33d2                 | mov                 edx, 0x10
            //   ff15????????         |                     
            //   48895f08             | jmp                 0x62
            //   33f6                 | and                 dword ptr [esp + 0xa8], 0
            //   eb12                 | and                 dword ptr [esp + 0x28], 0
            //   488b0d????????       |                     

        $sequence_22 = { b9e74b700f e8???????? 4885c0 7422 ba10000000 }
            // n = 5, score = 300
            //   b9e74b700f           | add                 eax, 1
            //   e8????????           |                     
            //   4885c0               | cmp                 edx, 0x10
            //   7422                 | jb                  0xfffffffb
            //   ba10000000           | mov                 dword ptr [esp + 0xa8], ecx

        $sequence_23 = { 740c 33d2 e8???????? 488bf8 eb02 }
            // n = 5, score = 300
            //   740c                 | je                  0xe
            //   33d2                 | xor                 edx, edx
            //   e8????????           |                     
            //   488bf8               | dec                 eax
            //   eb02                 | mov                 edi, eax

        $sequence_24 = { 897da0 89759c ffd3 83ec10 b900040000 ba02000000 }
            // n = 6, score = 100
            //   897da0               | mov                 al, byte ptr [ebp - 0x9d]
            //   89759c               | test                al, 1
            //   ffd3                 | jne                 0x60
            //   83ec10               | jmp                 6
            //   b900040000           | xor                 eax, eax
            //   ba02000000           | mov                 dword ptr [ebp - 0xa8], eax

        $sequence_25 = { 8b3d???????? 56 68ff030000 52 8bb5e0fbffff 56 8985d0fbffff }
            // n = 7, score = 100
            //   8b3d????????         |                     
            //   56                   | add                 eax, edx
            //   68ff030000           | test                eax, eax
            //   52                   | jne                 7
            //   8bb5e0fbffff         | cmp                 dword ptr [ebp - 4], eax
            //   56                   | jne                 0xffffffa6
            //   8985d0fbffff         | pop                 edi

        $sequence_26 = { 8945d8 31f6 8955d4 89f2 }
            // n = 4, score = 100
            //   8945d8               | add                 ecx, dword ptr [edx + 0x80]
            //   31f6                 | cmp                 ecx, 0
            //   8955d4               | mov                 dword ptr [esp + 4], eax
            //   89f2                 | mov                 ecx, 1

        $sequence_27 = { 28ca 88940556ffffff 83c001 83f814 8985ecfeffff 75d5 }
            // n = 6, score = 100
            //   28ca                 | jmp                 0x6b
            //   88940556ffffff       | mov                 dword ptr [ebp - 0x20], edx
            //   83c001               | je                  0x13d
            //   83f814               | xor                 eax, eax
            //   8985ecfeffff         | mov                 ecx, dword ptr [ebp - 0x14]
            //   75d5                 | mov                 edx, dword ptr [ebp - 0x18]

        $sequence_28 = { ffd6 8d0d2a318702 8b9568fdffff 891424 894c2404 898554fdffff e8???????? }
            // n = 7, score = 100
            //   ffd6                 | mov                 ebx, dword ptr [esi + 0x10]
            //   8d0d2a318702         | mov                 ecx, dword ptr [eax + 8]
            //   8b9568fdffff         | push                dword ptr [eax + 4]
            //   891424               | add                 ecx, dword ptr [esp + 0xc]
            //   894c2404             | mov                 eax, dword ptr [eax]
            //   898554fdffff         | push                ecx
            //   e8????????           |                     

        $sequence_29 = { 8b45a8 8b4da4 8d1549342500 83c207 89c6 83c601 89cf }
            // n = 7, score = 100
            //   8b45a8               | lea                 edx, [0x25353a]
            //   8b4da4               | mov                 esi, 0x14
            //   8d1549342500         | lea                 edi, [0x253489]
            //   83c207               | mov                 ebx, dword ptr [ebp - 0xb0]
            //   89c6                 | mov                 dword ptr [ebp - 0x10], ecx
            //   83c601               | mov                 dword ptr [ebp - 0x14], edx
            //   89cf                 | je                  9

        $sequence_30 = { 83f803 8945ec 75d0 e8???????? 31c9 83f800 }
            // n = 6, score = 100
            //   83f803               | cmp                 eax, dword ptr [esi + 0xc]
            //   8945ec               | jb                  0x4c
            //   75d0                 | mov                 edi, dword ptr [ecx + 0x38]
            //   e8????????           |                     
            //   31c9                 | mov                 eax, dword ptr [esi + 8]
            //   83f800               | mov                 edx, dword ptr [ecx + 0x3c]

        $sequence_31 = { 894df0 8955ec 7407 31c0 8945e8 eb0a }
            // n = 6, score = 100
            //   894df0               | push                esi
            //   8955ec               | jmp                 0xc
            //   7407                 | mov                 eax, dword ptr [ecx + 0x38]
            //   31c0                 | mov                 edx, dword ptr [esi + 8]
            //   8945e8               | lea                 edx, [eax + edx - 1]
            //   eb0a                 | dec                 eax

        $sequence_32 = { 8955e0 0f8437010000 31c0 8b4dec 8b55e8 038a80000000 83f900 }
            // n = 7, score = 100
            //   8955e0               | mov                 dword ptr [ecx + 4], esi
            //   0f8437010000         | mov                 ecx, dword ptr [eax + 8]
            //   31c0                 | push                dword ptr [eax + 4]
            //   8b4dec               | add                 ecx, dword ptr [esp + 0xc]
            //   8b55e8               | mov                 eax, dword ptr [eax]
            //   038a80000000         | add                 esi, 0x28
            //   83f900               | dec                 dword ptr [ebp - 4]

        $sequence_33 = { 8a8563ffffff a801 755c eb00 31c0 898558ffffff eb5b }
            // n = 7, score = 100
            //   8a8563ffffff         | not                 edx
            //   a801                 | mov                 edi, dword ptr [ecx + 0x38]
            //   755c                 | mov                 eax, dword ptr [esi + 8]
            //   eb00                 | mov                 edx, dword ptr [ecx + 0x3c]
            //   31c0                 | mov                 ebx, dword ptr [esi + 0x10]
            //   898558ffffff         | lea                 eax, [eax + edi - 1]
            //   eb5b                 | dec                 edi

        $sequence_34 = { 8b4858 8b5054 891424 894c2404 8945f0 e8???????? 8d0d84308702 }
            // n = 7, score = 100
            //   8b4858               | add                 eax, 0x20
            //   8b5054               | cmp                 eax, 3
            //   891424               | mov                 dword ptr [ebp - 0x14], eax
            //   894c2404             | jne                 0xffffffd5
            //   8945f0               | xor                 ecx, ecx
            //   e8????????           |                     
            //   8d0d84308702         | cmp                 eax, 0

        $sequence_35 = { 83c40c 8b45b4 8b486c 894ddc 8b4870 }
            // n = 5, score = 100
            //   83c40c               | pop                 esi
            //   8b45b4               | pop                 ebx
            //   8b486c               | jae                 0x15
            //   894ddc               | bt                  dword ptr [esi], 0x1f
            //   8b4870               | setb                al

        $sequence_36 = { 8d0d84308702 31d2 8b75f0 89461c 890c24 c744240400000000 }
            // n = 6, score = 100
            //   8d0d84308702         | push                esi
            //   31d2                 | push                0x3ff
            //   8b75f0               | push                edx
            //   89461c               | mov                 esi, dword ptr [ebp - 0x420]
            //   890c24               | push                esi
            //   c744240400000000     | mov                 dword ptr [ebp - 0x430], eax

        $sequence_37 = { 31c0 31c9 8945fc 894df8 e8???????? 89c1 83e8ff }
            // n = 7, score = 100
            //   31c0                 | call                esi
            //   31c9                 | lea                 ecx, [0x287312a]
            //   8945fc               | mov                 edx, dword ptr [ebp - 0x298]
            //   894df8               | mov                 dword ptr [esp], edx
            //   e8????????           |                     
            //   89c1                 | mov                 dword ptr [esp + 4], ecx
            //   83e8ff               | mov                 dword ptr [ebp - 0x2ac], eax

        $sequence_38 = { 89442404 e8???????? b901000000 8d153a352500 be14000000 8d3d89342500 8b9d50ffffff }
            // n = 7, score = 100
            //   89442404             | test                eax, eax
            //   e8????????           |                     
            //   b901000000           | jne                 0xc
            //   8d153a352500         | cmp                 dword ptr [ebp - 4], eax
            //   be14000000           | push                ebx
            //   8d3d89342500         | mov                 dword ptr [ebp - 4], eax
            //   8b9d50ffffff         | movzx               eax, word ptr [ecx + 0x14]

        $sequence_39 = { e8???????? 8d0d5b318702 890424 894c2404 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   8d0d5b318702         | neg                 al
            //   890424               | sbb                 eax, eax
            //   894c2404             | and                 eax, 0x20

    condition:
        7 of them and filesize < 221184
}