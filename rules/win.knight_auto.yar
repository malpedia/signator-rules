rule win_knight_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.knight."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.knight"
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
        $sequence_0 = { e8???????? 4889842438040000 48895c2438 488d05b7dc2b00 e8???????? 488b4c2468 48894808 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   4889842438040000     | xor                 edi, edi
            //   48895c2438           | dec                 eax
            //   488d05b7dc2b00       | mov                 dword ptr [esp + 0x58], 0
            //   e8????????           |                     
            //   488b4c2468           | mov                 eax, 0xb
            //   48894808             | mov                 ecx, 0x56

        $sequence_1 = { c3 4889b4fa90100000 4c8984fa98100000 48ffc0 48398280100000 0f8e41020000 488d3440 }
            // n = 7, score = 100
            //   c3                   | dec                 eax
            //   4889b4fa90100000     | mov                 dword ptr [eax + 8], ecx
            //   4c8984fa98100000     | jne                 0x69f
            //   48ffc0               | dec                 eax
            //   48398280100000       | lea                 edi, [eax + 0x18]
            //   0f8e41020000         | dec                 eax
            //   488d3440             | mov                 ecx, dword ptr [esp + 0x14e8]

        $sequence_2 = { e8???????? 90 48badc5618b3c5c35016 48899424d0010000 48bac41447e86e4d2c6e 48899424d8010000 48ba681b6b8416537508 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   90                   | dec                 eax
            //   48badc5618b3c5c35016     | mov    dword ptr [esp + 0x120], esi
            //   48899424d0010000     | dec                 eax
            //   48bac41447e86e4d2c6e     | mov    dword ptr [esp + 0xd0], edx
            //   48899424d8010000     | dec                 ecx
            //   48ba681b6b8416537508     | mov    eax, esi

        $sequence_3 = { eb11 488d7818 488b8c2490180000 e8???????? 488b8c24f8090000 48894808 833d????????00 }
            // n = 7, score = 100
            //   eb11                 | mov                 ecx, dword ptr [esp + 0x138]
            //   488d7818             | dec                 esp
            //   488b8c2490180000     | mov                 edx, dword ptr [esp + 0x50]
            //   e8????????           |                     
            //   488b8c24f8090000     | dec                 esp
            //   48894808             | mov                 dword ptr [eax + 0x20], edx
            //   833d????????00       |                     

        $sequence_4 = { 90 e9???????? 4d89e0 e8???????? e9???????? 0fb6542447 488b4c2470 }
            // n = 7, score = 100
            //   90                   | dec                 eax
            //   e9????????           |                     
            //   4d89e0               | mov                 dword ptr [eax], 0
            //   e8????????           |                     
            //   e9????????           |                     
            //   0fb6542447           | dec                 eax
            //   488b4c2470           | lea                 eax, [0xe2dd4]

        $sequence_5 = { e8???????? e9???????? 488b15???????? 83ba40010000ff 7524 488b942420010000 488d3452 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   e9????????           |                     
            //   488b15????????       |                     
            //   83ba40010000ff       | dec                 ebp
            //   7524                 | test                ebp, ebp
            //   488b942420010000     | je                  0x1426
            //   488d3452             | dec                 eax

        $sequence_6 = { e8???????? 488b842460010000 e8???????? 48898c24f0000000 48897c2468 488b942418010000 488d7208 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488b842460010000     | dec                 ecx
            //   e8????????           |                     
            //   48898c24f0000000     | cmp                 esp, dword ptr [esi + 0x10]
            //   48897c2468           | jbe                 0x15e7
            //   488b942418010000     | dec                 eax
            //   488d7208             | sub                 esp, 0x38

        $sequence_7 = { 48badde48c2f452788e5 488954247e 48ba44246115b6572ab9 4889942486000000 31c0 e9???????? 48894c2450 }
            // n = 7, score = 100
            //   48badde48c2f452788e5     | dec    eax
            //   488954247e           | mov                 ebx, dword ptr [esp + 0x50]
            //   48ba44246115b6572ab9     | dec    eax
            //   4889942486000000     | mov                 ebp, dword ptr [esp + 0x78]
            //   31c0                 | dec                 eax
            //   e9????????           |                     
            //   48894c2450           | sub                 esp, -0x80

        $sequence_8 = { 48baa24a6d7998292bba 488954242b 48ba58053529bf406a5d 4889542433 31c0 eb14 0fb654043b }
            // n = 7, score = 100
            //   48baa24a6d7998292bba     | arpl    cx, bx
            //   488954242b           | dec                 eax
            //   48ba58053529bf406a5d     | lea    eax, [esp + 0x44]
            //   4889542433           | dec                 eax
            //   31c0                 | mov                 ecx, ebx
            //   eb14                 | dec                 eax
            //   0fb654043b           | mov                 dword ptr [esp + 0x78], ecx

        $sequence_9 = { e8???????? 488d0542873200 bb14000000 6690 e8???????? 31c0 4889c1 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488d0542873200       | mov                 dword ptr [esp + 0x58], edx
            //   bb14000000           | dec                 esp
            //   6690                 | mov                 edi, dword ptr [esp + 0x68]
            //   e8????????           |                     
            //   31c0                 | dec                 ecx
            //   4889c1               | cmp                 eax, 0x20000000

    condition:
        7 of them and filesize < 12149760
}