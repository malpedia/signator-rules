rule win_strifewater_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.strifewater_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.strifewater_rat"
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
        $sequence_0 = { f30f5e05???????? f30f2cc8 448d400a 488d9560040000 e8???????? 488d8d68040000 492bcf }
            // n = 7, score = 100
            //   f30f5e05????????     |                     
            //   f30f2cc8             | inc                 ebp
            //   448d400a             | xor                 eax, eax
            //   488d9560040000       | xor                 edx, edx
            //   e8????????           |                     
            //   488d8d68040000       | dec                 eax
            //   492bcf               | mov                 ecx, ebx

        $sequence_1 = { 90 488d3d33710800 48897df8 488d4df8 e8???????? 90 eb19 }
            // n = 7, score = 100
            //   90                   | nop                 
            //   488d3d33710800       | dec                 eax
            //   48897df8             | mov                 ebx, dword ptr [esp + 0x40]
            //   488d4df8             | dec                 eax
            //   e8????????           |                     
            //   90                   | mov                 ecx, dword ptr [edi + 0x10]
            //   eb19                 | test                eax, eax

        $sequence_2 = { 66890451 48ffc2 6685c0 75ef 4c8d8d900f0000 4c8d442440 }
            // n = 6, score = 100
            //   66890451             | inc                 ebp
            //   48ffc2               | mov                 dword ptr [edi + 8], esi
            //   6685c0               | or                  eax, 0xffffffff
            //   75ef                 | lock xadd           dword ptr [ebx + 0x10], eax
            //   4c8d8d900f0000       | sub                 eax, 1
            //   4c8d442440           | jg                  0x1fda

        $sequence_3 = { 83c8ff f00fc101 83f801 751c 488b45e8 488b8888000000 488d05117f0300 }
            // n = 7, score = 100
            //   83c8ff               | dec                 eax
            //   f00fc101             | mov                 ebx, edx
            //   83f801               | dec                 esp
            //   751c                 | mov                 esi, ecx
            //   488b45e8             | and                 dword ptr [eax - 0x48], 0
            //   488b8888000000       | dec                 esp
            //   488d05117f0300       | lea                 ecx, [0x65204]

        $sequence_4 = { 7413 488d05a2b70600 8a0401 418807 49ffc7 41ffc4 b001 }
            // n = 7, score = 100
            //   7413                 | test                eax, eax
            //   488d05a2b70600       | jne                 0x871
            //   8a0401               | inc                 ecx
            //   418807               | movzx               eax, ax
            //   49ffc7               | dec                 esi
            //   41ffc4               | lea                 edi, [eax + esi]
            //   b001                 | dec                 ebp

        $sequence_5 = { 0f85b0000000 3bd9 0f85a8000000 488d5ee8 488b0b 488b01 }
            // n = 6, score = 100
            //   0f85b0000000         | test                dh, dh
            //   3bd9                 | dec                 eax
            //   0f85a8000000         | lea                 ebx, [0x57d3d]
            //   488d5ee8             | inc                 ecx
            //   488b0b               | and                 eax, 0x3f
            //   488b01               | dec                 ecx

        $sequence_6 = { e9???????? 488d8a90020000 e9???????? 488d8a90000000 e9???????? 488d8a90020000 }
            // n = 6, score = 100
            //   e9????????           |                     
            //   488d8a90020000       | dec                 eax
            //   e9????????           |                     
            //   488d8a90000000       | mov                 edx, dword ptr [ebp - 0x10]
            //   e9????????           |                     
            //   488d8a90020000       | dec                 eax

        $sequence_7 = { 7434 4863cb 0f1005???????? 0f110401 f20f100d???????? f20f114c0110 0fb705???????? }
            // n = 7, score = 100
            //   7434                 | jne                 0xfba
            //   4863cb               | test                edx, edx
            //   0f1005????????       |                     
            //   0f110401             | je                  0xfd0
            //   f20f100d????????     |                     
            //   f20f114c0110         | dec                 eax
            //   0fb705????????       |                     

        $sequence_8 = { 498b4e08 4c8d4508 33d2 ff15???????? 488b7508 4c8d4530 488bce }
            // n = 7, score = 100
            //   498b4e08             | dec                 eax
            //   4c8d4508             | add                 eax, eax
            //   33d2                 | movzx               ecx, word ptr [eax + ebx]
            //   ff15????????         |                     
            //   488b7508             | inc                 cx
            //   4c8d4530             | cmp                 ecx, ecx
            //   488bce               | jne                 0x35c

        $sequence_9 = { 894350 eb12 488d0d4eeb0200 c7435006000000 48894b48 c6435400 488b5c2430 }
            // n = 7, score = 100
            //   894350               | lea                 eax, [eax + 0x14]
            //   eb12                 | dec                 eax
            //   488d0d4eeb0200       | lea                 edx, [ebp + 0x1f40]
            //   c7435006000000       | dec                 eax
            //   48894b48             | lea                 ecx, [ebp + 0x1c8]
            //   c6435400             | dec                 eax
            //   488b5c2430           | mov                 dword ptr [ebp + 0x8e0], eax

    condition:
        7 of them and filesize < 1552384
}