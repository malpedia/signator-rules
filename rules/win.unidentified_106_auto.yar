rule win_unidentified_106_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.unidentified_106."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_106"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
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
        $sequence_0 = { e8???????? 33c0 eb2a bdfdffffff 4d85e4 741e 4585ed }
            // n = 7, score = 100
            //   e8????????           |                     
            //   33c0                 | inc                 esp
            //   eb2a                 | mov                 esi, ecx
            //   bdfdffffff           | dec                 esp
            //   4d85e4               | mov                 ebx, ecx
            //   741e                 | inc                 ebp
            //   4585ed               | mov                 edx, eax

        $sequence_1 = { f7d7 4881ffb057c96e 410fbff0 48bffd4d2301f6224375 488b7c2428 488b3f ff742408 }
            // n = 7, score = 100
            //   f7d7                 | dec                 eax
            //   4881ffb057c96e       | add                 esp, 0x40
            //   410fbff0             | inc                 ecx
            //   48bffd4d2301f6224375     | pop    edi
            //   488b7c2428           | inc                 ecx
            //   488b3f               | pop                 esi
            //   ff742408             | inc                 ecx

        $sequence_2 = { c3 44886814 4c8d842480000000 8d4701 b20d 488bcb 6689842480000000 }
            // n = 7, score = 100
            //   c3                   | dec                 ebp
            //   44886814             | cmp                 esi, eax
            //   4c8d842480000000     | jge                 0xdd5
            //   8d4701               | dec                 ebx
            //   b20d                 | lea                 eax, [esi + esi*2]
            //   488bcb               | dec                 eax
            //   6689842480000000     | lea                 edx, [eax*8]

        $sequence_3 = { 8bc1 c1e810 884201 8bc1 c1e808 884202 c6020b }
            // n = 7, score = 100
            //   8bc1                 | inc                 ecx
            //   c1e810               | mov                 eax, esi
            //   884201               | dec                 ebp
            //   8bc1                 | lea                 ecx, [ebp + 0x10]
            //   c1e808               | dec                 esp
            //   884202               | lea                 edi, [0x37d88]
            //   c6020b               | inc                 ecx

        $sequence_4 = { e8???????? 448bf0 85c0 7410 488bcb e8???????? 418bc6 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   448bf0               | mov                 edx, 0x70
            //   85c0                 | dec                 eax
            //   7410                 | mov                 ecx, ebx
            //   488bcb               | dec                 esp
            //   e8????????           |                     
            //   418bc6               | lea                 eax, [0x240bb4]

        $sequence_5 = { f20f59f1 f20f587330 0f28c6 f20f5c4328 660f2f4320 7612 4c8b4318 }
            // n = 7, score = 100
            //   f20f59f1             | cmp                 eax, edx
            //   f20f587330           | ja                  0x16ae
            //   0f28c6               | inc                 ecx
            //   f20f5c4328           | cmp                 eax, 4
            //   660f2f4320           | ja                  0x16ae
            //   7612                 | jb                  0x16e6
            //   4c8b4318             | dec                 eax

        $sequence_6 = { befdffffff e9???????? 4c8b642448 befeffffff 4c8b6c2428 e9???????? 4c8b642448 }
            // n = 7, score = 100
            //   befdffffff           | dec                 eax
            //   e9????????           |                     
            //   4c8b642448           | mov                 ecx, edi
            //   befeffffff           | dec                 eax
            //   4c8b6c2428           | test                eax, eax
            //   e9????????           |                     
            //   4c8b642448           | jns                 0x1b12

        $sequence_7 = { 498bcf e8???????? 85c0 0f8ef1000000 48837f5000 8b442434 894710 }
            // n = 7, score = 100
            //   498bcf               | shl                 eax, 8
            //   e8????????           |                     
            //   85c0                 | inc                 esp
            //   0f8ef1000000         | or                  eax, edx
            //   48837f5000           | inc                 esp
            //   8b442434             | mov                 dword ptr [ebp - 0x1c], ecx
            //   894710               | inc                 ebp

        $sequence_8 = { 48ffca 66c1e908 6685c9 75e3 418bf6 ff07 488b9c2428010000 }
            // n = 7, score = 100
            //   48ffca               | test                eax, eax
            //   66c1e908             | jne                 0x6ea
            //   6685c9               | dec                 eax
            //   75e3                 | add                 edi, 3
            //   418bf6               | inc                 ecx
            //   ff07                 | mov                 eax, 3
            //   488b9c2428010000     | dec                 eax

        $sequence_9 = { e8???????? 488b9ed8000000 49c7c4ffffffff 44897d48 4c8be8 44897d50 4d8bf4 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488b9ed8000000       | dec                 ecx
            //   49c7c4ffffffff       | mov                 edx, esi
            //   44897d48             | dec                 eax
            //   4c8be8               | lea                 ecx, [ebp - 0x29]
            //   44897d50             | mov                 esi, eax
            //   4d8bf4               | test                eax, eax

    condition:
        7 of them and filesize < 27402240
}