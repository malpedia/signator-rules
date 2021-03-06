rule win_helminth_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.helminth."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.helminth"
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
        $sequence_0 = { a1???????? 68e8030000 8907 e8???????? }
            // n = 4, score = 300
            //   a1????????           |                     
            //   68e8030000           | push                0x3e8
            //   8907                 | mov                 dword ptr [edi], eax
            //   e8????????           |                     

        $sequence_1 = { 7425 6a00 6a00 6a00 6afd }
            // n = 5, score = 200
            //   7425                 | je                  0x27
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6afd                 | push                -3

        $sequence_2 = { 668b444b0c 6689044d1c7f0110 41 ebe8 8bce 894de4 }
            // n = 6, score = 200
            //   668b444b0c           | mov                 ax, word ptr [ebx + ecx*2 + 0xc]
            //   6689044d1c7f0110     | mov                 word ptr [ecx*2 + 0x10017f1c], ax
            //   41                   | inc                 ecx
            //   ebe8                 | jmp                 0xffffffea
            //   8bce                 | mov                 ecx, esi
            //   894de4               | mov                 dword ptr [ebp - 0x1c], ecx

        $sequence_3 = { 8bf0 83c410 85f6 7409 0f57c0 f30f7f06 eb02 }
            // n = 7, score = 200
            //   8bf0                 | mov                 esi, eax
            //   83c410               | add                 esp, 0x10
            //   85f6                 | test                esi, esi
            //   7409                 | je                  0xb
            //   0f57c0               | xorps               xmm0, xmm0
            //   f30f7f06             | movdqu              xmmword ptr [esi], xmm0
            //   eb02                 | jmp                 4

        $sequence_4 = { 6aff ff35???????? 66893441 8b1a ff15???????? 8bc3 8d5002 }
            // n = 7, score = 200
            //   6aff                 | push                -1
            //   ff35????????         |                     
            //   66893441             | mov                 word ptr [ecx + eax*2], si
            //   8b1a                 | mov                 ebx, dword ptr [edx]
            //   ff15????????         |                     
            //   8bc3                 | mov                 eax, ebx
            //   8d5002               | lea                 edx, [eax + 2]

        $sequence_5 = { c1e106 8b048570750110 804c080420 8b4d14 }
            // n = 4, score = 200
            //   c1e106               | shl                 ecx, 6
            //   8b048570750110       | mov                 eax, dword ptr [eax*4 + 0x10017570]
            //   804c080420           | or                  byte ptr [eax + ecx + 4], 0x20
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]

        $sequence_6 = { 8bd0 83c40c 8b4508 8bf2 2bf0 8d642400 0fb708 }
            // n = 7, score = 200
            //   8bd0                 | mov                 edx, eax
            //   83c40c               | add                 esp, 0xc
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8bf2                 | mov                 esi, edx
            //   2bf0                 | sub                 esi, eax
            //   8d642400             | lea                 esp, [esp]
            //   0fb708               | movzx               ecx, word ptr [eax]

        $sequence_7 = { c705????????c3de0010 c705????????48df0010 a3???????? c705????????0dd50010 c705????????81de0010 c705????????e9dd0010 }
            // n = 6, score = 200
            //   c705????????c3de0010     |     
            //   c705????????48df0010     |     
            //   a3????????           |                     
            //   c705????????0dd50010     |     
            //   c705????????81de0010     |     
            //   c705????????e9dd0010     |     

        $sequence_8 = { 897dec 66891448 6683387e 0f855f020000 8b75d8 }
            // n = 5, score = 100
            //   897dec               | mov                 dword ptr [ebp - 0x14], edi
            //   66891448             | mov                 word ptr [eax + ecx*2], dx
            //   6683387e             | cmp                 word ptr [eax], 0x7e
            //   0f855f020000         | jne                 0x265
            //   8b75d8               | mov                 esi, dword ptr [ebp - 0x28]

        $sequence_9 = { a1???????? 8907 33ff 894df8 668b02 }
            // n = 5, score = 100
            //   a1????????           |                     
            //   8907                 | mov                 dword ptr [edi], eax
            //   33ff                 | xor                 edi, edi
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   668b02               | mov                 ax, word ptr [edx]

        $sequence_10 = { 880c17 42 84c9 75f6 e8???????? }
            // n = 5, score = 100
            //   880c17               | mov                 byte ptr [edi + edx], cl
            //   42                   | inc                 edx
            //   84c9                 | test                cl, cl
            //   75f6                 | jne                 0xfffffff8
            //   e8????????           |                     

        $sequence_11 = { 0f8450030000 8b8528e5ffff 8b8d24e5ffff 8b048528eb4100 f644010480 0f8432030000 }
            // n = 6, score = 100
            //   0f8450030000         | je                  0x356
            //   8b8528e5ffff         | mov                 eax, dword ptr [ebp - 0x1ad8]
            //   8b8d24e5ffff         | mov                 ecx, dword ptr [ebp - 0x1adc]
            //   8b048528eb4100       | mov                 eax, dword ptr [eax*4 + 0x41eb28]
            //   f644010480           | test                byte ptr [ecx + eax + 4], 0x80
            //   0f8432030000         | je                  0x338

        $sequence_12 = { 8b0d???????? 8b0c8d20f04100 e8???????? 33db 8bf0 53 }
            // n = 6, score = 100
            //   8b0d????????         |                     
            //   8b0c8d20f04100       | mov                 ecx, dword ptr [ecx*4 + 0x41f020]
            //   e8????????           |                     
            //   33db                 | xor                 ebx, ebx
            //   8bf0                 | mov                 esi, eax
            //   53                   | push                ebx

        $sequence_13 = { ff35???????? 89742438 e8???????? 8bd3 }
            // n = 4, score = 100
            //   ff35????????         |                     
            //   89742438             | mov                 dword ptr [esp + 0x38], esi
            //   e8????????           |                     
            //   8bd3                 | mov                 edx, ebx

        $sequence_14 = { 56 e8???????? 8bfe 8945f4 }
            // n = 4, score = 100
            //   56                   | push                esi
            //   e8????????           |                     
            //   8bfe                 | mov                 edi, esi
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax

    condition:
        7 of them and filesize < 479232
}