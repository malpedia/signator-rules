rule win_nymaim_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.nymaim."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nymaim"
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
        $sequence_0 = { 89d8 01c8 31d2 f7f7 }
            // n = 4, score = 1800
            //   89d8                 | mov                 eax, ebx
            //   01c8                 | add                 eax, ecx
            //   31d2                 | xor                 edx, edx
            //   f7f7                 | div                 edi

        $sequence_1 = { 0f94c1 09c8 6bc064 09c0 }
            // n = 4, score = 1700
            //   0f94c1               | sete                cl
            //   09c8                 | or                  eax, ecx
            //   6bc064               | imul                eax, eax, 0x64
            //   09c0                 | or                  eax, eax

        $sequence_2 = { 31d2 f7f7 92 31d2 bf64000000 }
            // n = 5, score = 1700
            //   31d2                 | xor                 edx, edx
            //   f7f7                 | div                 edi
            //   92                   | xchg                eax, edx
            //   31d2                 | xor                 edx, edx
            //   bf64000000           | mov                 edi, 0x64

        $sequence_3 = { c1e902 740d 8b06 8907 }
            // n = 4, score = 1600
            //   c1e902               | shr                 ecx, 2
            //   740d                 | je                  0xf
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8907                 | mov                 dword ptr [edi], eax

        $sequence_4 = { 31d2 bf64000000 f7f7 5b 5f }
            // n = 5, score = 1600
            //   31d2                 | xor                 edx, edx
            //   bf64000000           | mov                 edi, 0x64
            //   f7f7                 | div                 edi
            //   5b                   | pop                 ebx
            //   5f                   | pop                 edi

        $sequence_5 = { c1eb13 331d???????? 31c3 c1e808 }
            // n = 4, score = 1600
            //   c1eb13               | shr                 ebx, 0x13
            //   331d????????         |                     
            //   31c3                 | xor                 ebx, eax
            //   c1e808               | shr                 eax, 8

        $sequence_6 = { 31c9 38f0 83d100 38d0 83d900 c1e105 }
            // n = 6, score = 1600
            //   31c9                 | xor                 ecx, ecx
            //   38f0                 | cmp                 al, dh
            //   83d100               | adc                 ecx, 0
            //   38d0                 | cmp                 al, dl
            //   83d900               | sbb                 ecx, 0
            //   c1e105               | shl                 ecx, 5

        $sequence_7 = { c1e105 01c8 c1c307 30c3 }
            // n = 4, score = 1600
            //   c1e105               | shl                 ecx, 5
            //   01c8                 | add                 eax, ecx
            //   c1c307               | rol                 ebx, 7
            //   30c3                 | xor                 bl, al

        $sequence_8 = { 00d3 8a16 301e 46 }
            // n = 4, score = 1300
            //   00d3                 | add                 bl, dl
            //   8a16                 | mov                 dl, byte ptr [esi]
            //   301e                 | xor                 byte ptr [esi], bl
            //   46                   | inc                 esi

        $sequence_9 = { 8b5514 8b12 8b4d0c 8b5d18 8b1b 4f }
            // n = 6, score = 1100
            //   8b5514               | mov                 edx, dword ptr [ebp + 0x14]
            //   8b12                 | mov                 edx, dword ptr [edx]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8b5d18               | mov                 ebx, dword ptr [ebp + 0x18]
            //   8b1b                 | mov                 ebx, dword ptr [ebx]
            //   4f                   | dec                 edi

        $sequence_10 = { 8b1b 4f 31c0 fec2 }
            // n = 4, score = 1100
            //   8b1b                 | mov                 ebx, dword ptr [ebx]
            //   4f                   | dec                 edi
            //   31c0                 | xor                 eax, eax
            //   fec2                 | inc                 dl

        $sequence_11 = { f7e0 0fc8 01d0 894704 0307 }
            // n = 5, score = 1100
            //   f7e0                 | mul                 eax
            //   0fc8                 | bswap               eax
            //   01d0                 | add                 eax, edx
            //   894704               | mov                 dword ptr [edi + 4], eax
            //   0307                 | add                 eax, dword ptr [edi]

        $sequence_12 = { 8b4e08 014e04 8b5e0c 015e08 }
            // n = 4, score = 1100
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]
            //   014e04               | add                 dword ptr [esi + 4], ecx
            //   8b5e0c               | mov                 ebx, dword ptr [esi + 0xc]
            //   015e08               | add                 dword ptr [esi + 8], ebx

        $sequence_13 = { 8b06 c1e00b 3306 8b5604 0116 }
            // n = 5, score = 1100
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   c1e00b               | shl                 eax, 0xb
            //   3306                 | xor                 eax, dword ptr [esi]
            //   8b5604               | mov                 edx, dword ptr [esi + 4]
            //   0116                 | add                 dword ptr [esi], edx

        $sequence_14 = { 31d2 890c24 c744240400000000 8945f4 8955f0 e8???????? 8d0d8630d201 }
            // n = 7, score = 100
            //   31d2                 | xor                 edx, edx
            //   890c24               | mov                 dword ptr [esp], ecx
            //   c744240400000000     | mov                 dword ptr [esp + 4], 0
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8955f0               | mov                 dword ptr [ebp - 0x10], edx
            //   e8????????           |                     
            //   8d0d8630d201         | lea                 ecx, [0x1d23086]

        $sequence_15 = { 55 89e5 83ec10 8b4508 8d0d3430d201 }
            // n = 5, score = 100
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   83ec10               | sub                 esp, 0x10
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8d0d3430d201         | lea                 ecx, [0x1d23034]

        $sequence_16 = { 5b 5d c3 8b45f0 8b0c850440d201 }
            // n = 5, score = 100
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8b0c850440d201       | mov                 ecx, dword ptr [eax*4 + 0x1d24004]

        $sequence_17 = { 4189c7 4189f1 e8???????? 4189f8 4489f9 66c705????????f167 488b8424c0000000 }
            // n = 7, score = 100
            //   4189c7               | inc                 esp
            //   4189f1               | and                 eax, ecx
            //   e8????????           |                     
            //   4189f8               | add                 edx, ecx
            //   4489f9               | dec                 eax
            //   66c705????????f167     |     
            //   488b8424c0000000     | mov                 ebx, eax

        $sequence_18 = { 53 56 57 83ec44 8b4508 8d0d2030d201 }
            // n = 6, score = 100
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   83ec44               | sub                 esp, 0x44
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8d0d2030d201         | lea                 ecx, [0x1d23020]

        $sequence_19 = { 01ca e8???????? 4889c3 4885c0 0f84fc000000 48894008 488900 }
            // n = 7, score = 100
            //   01ca                 | inc                 ecx
            //   e8????????           |                     
            //   4889c3               | xor                 ecx, ecx
            //   4885c0               | je                  0x1ce5f
            //   0f84fc000000         | mov                 eax, ebx
            //   48894008             | dec                 esp
            //   488900               | lea                 eax, [ebp + 0x38]

        $sequence_20 = { 31c9 8b55f4 8b75ec 89723c c7424003000000 }
            // n = 5, score = 100
            //   31c9                 | xor                 ecx, ecx
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   8b75ec               | mov                 esi, dword ptr [ebp - 0x14]
            //   89723c               | mov                 dword ptr [edx + 0x3c], esi
            //   c7424003000000       | mov                 dword ptr [edx + 0x40], 3

        $sequence_21 = { 890424 894c2404 e8???????? 8d0d3430d201 }
            // n = 4, score = 100
            //   890424               | mov                 dword ptr [esp], eax
            //   894c2404             | mov                 dword ptr [esp + 4], ecx
            //   e8????????           |                     
            //   8d0d3430d201         | lea                 ecx, [0x1d23034]

        $sequence_22 = { 4531c0 f6463810 0f84dd820200 803d????????cb 0f84366b0300 8b4340 394348 }
            // n = 7, score = 100
            //   4531c0               | mov                 dword ptr [eax + 8], eax
            //   f6463810             | dec                 eax
            //   0f84dd820200         | mov                 dword ptr [eax], eax
            //   803d????????cb       |                     
            //   0f84366b0300         | inc                 ecx
            //   8b4340               | mov                 edi, eax
            //   394348               | inc                 ecx

        $sequence_23 = { 0f859090ffff 4885db 0f85e94dffff 4585db 0f85b901feff 4889eb e9???????? }
            // n = 7, score = 100
            //   0f859090ffff         | mov                 ecx, esi
            //   4885db               | inc                 ecx
            //   0f85e94dffff         | mov                 eax, edi
            //   4585db               | inc                 esp
            //   0f85b901feff         | mov                 ecx, edi
            //   4889eb               | dec                 eax
            //   e9????????           |                     

        $sequence_24 = { 83ec44 8b4508 8d0d2030d201 31d2 890c24 c744240400000000 }
            // n = 6, score = 100
            //   83ec44               | sub                 esp, 0x44
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8d0d2030d201         | lea                 ecx, [0x1d23020]
            //   31d2                 | xor                 edx, edx
            //   890c24               | mov                 dword ptr [esp], ecx
            //   c744240400000000     | mov                 dword ptr [esp + 4], 0

        $sequence_25 = { 4131c9 803d????????71 0f8459ce0100 66d11d???????? 89d8 4c8d4538 4421c8 }
            // n = 7, score = 100
            //   4131c9               | add                 eax, 0x38
            //   803d????????71       |                     
            //   0f8459ce0100         | dec                 eax
            //   66d11d????????       |                     
            //   89d8                 | mov                 ebx, eax
            //   4c8d4538             | dec                 eax
            //   4421c8               | lea                 ecx, [ebp - 0x10]

        $sequence_26 = { 0f8527430000 83ff08 881d???????? 880d???????? 0f8261430000 b9a4614902 e8???????? }
            // n = 7, score = 100
            //   0f8527430000         | dec                 eax
            //   83ff08               | test                eax, eax
            //   881d????????         |                     
            //   880d????????         |                     
            //   0f8261430000         | je                  0x108
            //   b9a4614902           | dec                 eax
            //   e8????????           |                     

        $sequence_27 = { 44034224 7405 478d440004 4183c038 e8???????? 4889c3 488d4df0 }
            // n = 7, score = 100
            //   44034224             | inc                 esp
            //   7405                 | add                 eax, dword ptr [edx + 0x24]
            //   478d440004           | je                  7
            //   4183c038             | inc                 edi
            //   e8????????           |                     
            //   4889c3               | lea                 eax, [eax + eax + 4]
            //   488d4df0             | inc                 ecx

        $sequence_28 = { 56 83ec28 8b450c 8b4d08 8d154e30d201 }
            // n = 5, score = 100
            //   56                   | push                esi
            //   83ec28               | sub                 esp, 0x28
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8d154e30d201         | lea                 edx, [0x1d2304e]

        $sequence_29 = { 0f85531b0000 488d842480000000 448915???????? 4531c9 4889442428 8d573f 488d442470 }
            // n = 7, score = 100
            //   0f85531b0000         | mov                 eax, dword ptr [esp + 0xc0]
            //   488d842480000000     | jne                 0x432d
            //   448915????????       |                     
            //   4531c9               | cmp                 edi, 8
            //   4889442428           | jb                  0x436a
            //   8d573f               | mov                 ecx, 0x24961a4
            //   488d442470           | inc                 ebp

    condition:
        1 of them and filesize < 2375680
}