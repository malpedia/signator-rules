rule win_rekoobew_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.rekoobew."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rekoobew"
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
        $sequence_0 = { c1c01e 8b7db8 337dcc 337de0 337dd8 d1c7 }
            // n = 6, score = 100
            //   c1c01e               | rol                 eax, 0x1e
            //   8b7db8               | mov                 edi, dword ptr [ebp - 0x48]
            //   337dcc               | xor                 edi, dword ptr [ebp - 0x34]
            //   337de0               | xor                 edi, dword ptr [ebp - 0x20]
            //   337dd8               | xor                 edi, dword ptr [ebp - 0x28]
            //   d1c7                 | rol                 edi, 1

        $sequence_1 = { c740241cb04000 8910 c7401898654000 c7401ca06a4000 c74020a86a4000 }
            // n = 5, score = 100
            //   c740241cb04000       | mov                 dword ptr [eax + 0x24], 0x40b01c
            //   8910                 | mov                 dword ptr [eax], edx
            //   c7401898654000       | mov                 dword ptr [eax + 0x18], 0x406598
            //   c7401ca06a4000       | mov                 dword ptr [eax + 0x1c], 0x406aa0
            //   c74020a86a4000       | mov                 dword ptr [eax + 0x20], 0x406aa8

        $sequence_2 = { 0fb6da 8b1c9de0944000 335f10 89df 8b5dec c1eb18 8b1c9de0944000 }
            // n = 7, score = 100
            //   0fb6da               | movzx               ebx, dl
            //   8b1c9de0944000       | mov                 ebx, dword ptr [ebx*4 + 0x4094e0]
            //   335f10               | xor                 ebx, dword ptr [edi + 0x10]
            //   89df                 | mov                 edi, ebx
            //   8b5dec               | mov                 ebx, dword ptr [ebp - 0x14]
            //   c1eb18               | shr                 ebx, 0x18
            //   8b1c9de0944000       | mov                 ebx, dword ptr [ebx*4 + 0x4094e0]

        $sequence_3 = { 337dc8 337ddc 337dd4 d1c7 897dc8 8d8438dcbc1b8f }
            // n = 6, score = 100
            //   337dc8               | xor                 edi, dword ptr [ebp - 0x38]
            //   337ddc               | xor                 edi, dword ptr [ebp - 0x24]
            //   337dd4               | xor                 edi, dword ptr [ebp - 0x2c]
            //   d1c7                 | rol                 edi, 1
            //   897dc8               | mov                 dword ptr [ebp - 0x38], edi
            //   8d8438dcbc1b8f       | lea                 eax, dword ptr [eax + edi - 0x70e44324]

        $sequence_4 = { 0fb6f5 8b34b5e0784000 31fe 8975e0 0fb6f1 8b3cb5e07c4000 33bbac010000 }
            // n = 7, score = 100
            //   0fb6f5               | movzx               esi, ch
            //   8b34b5e0784000       | mov                 esi, dword ptr [esi*4 + 0x4078e0]
            //   31fe                 | xor                 esi, edi
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi
            //   0fb6f1               | movzx               esi, cl
            //   8b3cb5e07c4000       | mov                 edi, dword ptr [esi*4 + 0x407ce0]
            //   33bbac010000         | xor                 edi, dword ptr [ebx + 0x1ac]

        $sequence_5 = { 337b74 8b75ec c1ee18 333cb5e0844000 8b75e8 c1ee10 81e6ff000000 }
            // n = 7, score = 100
            //   337b74               | xor                 edi, dword ptr [ebx + 0x74]
            //   8b75ec               | mov                 esi, dword ptr [ebp - 0x14]
            //   c1ee18               | shr                 esi, 0x18
            //   333cb5e0844000       | xor                 edi, dword ptr [esi*4 + 0x4084e0]
            //   8b75e8               | mov                 esi, dword ptr [ebp - 0x18]
            //   c1ee10               | shr                 esi, 0x10
            //   81e6ff000000         | and                 esi, 0xff

        $sequence_6 = { 89f1 31d1 31d9 8d0c0f 89c7 c1c705 01f9 }
            // n = 7, score = 100
            //   89f1                 | mov                 ecx, esi
            //   31d1                 | xor                 ecx, edx
            //   31d9                 | xor                 ecx, ebx
            //   8d0c0f               | lea                 ecx, dword ptr [edi + ecx]
            //   89c7                 | mov                 edi, eax
            //   c1c705               | rol                 edi, 5
            //   01f9                 | add                 ecx, edi

        $sequence_7 = { c1eb18 8b1c9de0944000 c1e318 31de 89c3 c1eb10 0fb6db }
            // n = 7, score = 100
            //   c1eb18               | shr                 ebx, 0x18
            //   8b1c9de0944000       | mov                 ebx, dword ptr [ebx*4 + 0x4094e0]
            //   c1e318               | shl                 ebx, 0x18
            //   31de                 | xor                 esi, ebx
            //   89c3                 | mov                 ebx, eax
            //   c1eb10               | shr                 ebx, 0x10
            //   0fb6db               | movzx               ebx, bl

        $sequence_8 = { 890424 e8???????? 8b7d0c b800000000 b9ffffffff f2ae }
            // n = 6, score = 100
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]
            //   b800000000           | mov                 eax, 0
            //   b9ffffffff           | mov                 ecx, 0xffffffff
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]

        $sequence_9 = { 337dc8 337dc0 d1c7 897ddc 8d943adcbc1b8f 89c7 09df }
            // n = 7, score = 100
            //   337dc8               | xor                 edi, dword ptr [ebp - 0x38]
            //   337dc0               | xor                 edi, dword ptr [ebp - 0x40]
            //   d1c7                 | rol                 edi, 1
            //   897ddc               | mov                 dword ptr [ebp - 0x24], edi
            //   8d943adcbc1b8f       | lea                 edx, dword ptr [edx + edi - 0x70e44324]
            //   89c7                 | mov                 edi, eax
            //   09df                 | or                  edi, ebx

    condition:
        7 of them and filesize < 248832
}