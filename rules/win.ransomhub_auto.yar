rule win_ransomhub_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.ransomhub."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ransomhub"
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
        $sequence_0 = { 833d????????00 7509 48898780010000 eb15 488db780010000 4889f9 4889f7 }
            // n = 7, score = 100
            //   833d????????00       |                     
            //   7509                 | dec                 eax
            //   48898780010000       | mov                 dword ptr [esp + 0x118], ebx
            //   eb15                 | nop                 
            //   488db780010000       | dec                 eax
            //   4889f9               | mov                 ecx, dword ptr [esp + 0x5f0]
            //   4889f7               | dec                 eax

        $sequence_1 = { bf01000000 488d353b5f1c00 e8???????? 488b7c2458 48894f10 833d????????00 7506 }
            // n = 7, score = 100
            //   bf01000000           | mov                 ecx, dword ptr [esp + 0x78]
            //   488d353b5f1c00       | nop                 dword ptr [eax + eax]
            //   e8????????           |                     
            //   488b7c2458           | dec                 eax
            //   48894f10             | mov                 ebx, eax
            //   833d????????00       |                     
            //   7506                 | dec                 eax

        $sequence_2 = { 4939da 740d 4c89d0 b930000000 e8???????? 31c0 31db }
            // n = 7, score = 100
            //   4939da               | inc                 esp
            //   740d                 | movzx               edi, byte ptr [esp + 0x3b]
            //   4c89d0               | inc                 esp
            //   b930000000           | mov                 byte ptr [esp + 0x25], bh
            //   e8????????           |                     
            //   31c0                 | inc                 esp
            //   31db                 | movzx               edi, byte ptr [esp + 0x39]

        $sequence_3 = { 88543c1d 418d50ad 8854341d 4883c002 4883f81e 7d27 0fb6540432 }
            // n = 7, score = 100
            //   88543c1d             | dec                 eax
            //   418d50ad             | mov                 dword ptr [esp + 0x18], ecx
            //   8854341d             | dec                 eax
            //   4883c002             | mov                 ebx, eax
            //   4883f81e             | dec                 eax
            //   7d27                 | lea                 eax, [0x2b524a]
            //   0fb6540432           | dec                 eax

        $sequence_4 = { eb8d 0f1f00 e8???????? 488d0514b23900 bb10000000 e8???????? 488d05a2de3900 }
            // n = 7, score = 100
            //   eb8d                 | mov                 dword ptr [esp + 0x28], eax
            //   0f1f00               | dec                 eax
            //   e8????????           |                     
            //   488d0514b23900       | mov                 dword ptr [eax], 0
            //   bb10000000           | dec                 eax
            //   e8????????           |                     
            //   488d05a2de3900       | lea                 eax, [0x1bc714]

        $sequence_5 = { c3 e8???????? 0f1f440000 e8???????? 4889c3 488d0531862000 e8???????? }
            // n = 7, score = 100
            //   c3                   | dec                 eax
            //   e8????????           |                     
            //   0f1f440000           | add                 esp, 0x18
            //   e8????????           |                     
            //   4889c3               | ret                 
            //   488d0531862000       | dec                 eax
            //   e8????????           |                     

        $sequence_6 = { 752e 4c8b8424380b0000 4c8944d0d8 488d14d0 488d52e0 0f108424400b0000 0f1102 }
            // n = 7, score = 100
            //   752e                 | nop                 
            //   4c8b8424380b0000     | inc                 eax
            //   4c8944d0d8           | test                dh, 4
            //   488d14d0             | je                  0x176a
            //   488d52e0             | dec                 eax
            //   0f108424400b0000     | lea                 eax, [0x3a6373]
            //   0f1102               | mov                 ebx, 0x21

        $sequence_7 = { bf01000000 488d35142c2800 e8???????? 4c8b442450 4c8b4c2440 4889da 4889c7 }
            // n = 7, score = 100
            //   bf01000000           | dec                 eax
            //   488d35142c2800       | mov                 esi, dword ptr [esp + 0x58]
            //   e8????????           |                     
            //   4c8b442450           | dec                 esp
            //   4c8b4c2440           | mov                 eax, dword ptr [esp + 0x38]
            //   4889da               | inc                 ecx
            //   4889c7               | mov                 ecx, 5

        $sequence_8 = { e8???????? 450f57ff 4c8b35???????? 654d8b36 4d8b36 488d0538d53800 bb33000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   450f57ff             | xor                 eax, eax
            //   4c8b35????????       |                     
            //   654d8b36             | inc                 ebp
            //   4d8b36               | xor                 ecx, ecx
            //   488d0538d53800       | xor                 eax, eax
            //   bb33000000           | dec                 eax

        $sequence_9 = { 4c0f4ce7 4d39e3 7dc4 4c8b7828 4d29fa 4c8b7818 4d0fafd7 }
            // n = 7, score = 100
            //   4c0f4ce7             | cmp                 ebx, 2
            //   4d39e3               | jg                  0xa10
            //   7dc4                 | dec                 eax
            //   4c8b7828             | cmp                 esi, edi
            //   4d29fa               | ja                  0xaf4
            //   4c8b7818             | dec                 eax
            //   4d0fafd7             | mov                 dword ptr [esp + 0x60], ebx

    condition:
        7 of them and filesize < 12821504
}