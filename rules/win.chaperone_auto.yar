rule win_chaperone_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.chaperone."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chaperone"
        malpedia_rule_date = "20230124"
        malpedia_hash = "2ee0eebba83dce3d019a90519f2f972c0fcf9686"
        malpedia_version = "20230125"
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
        $sequence_0 = { 389c2498000000 740f 488b842490000000 83a0c8000000fd 8bc6 eb98 48895c2408 }
            // n = 7, score = 100
            //   389c2498000000       | lea                 edx, [0xb4be]
            //   740f                 | dec                 eax
            //   488b842490000000     | mov                 ecx, esi
            //   83a0c8000000fd       | dec                 eax
            //   8bc6                 | mov                 eax, esi
            //   eb98                 | dec                 eax
            //   48895c2408           | lea                 edx, [0x1944b]

        $sequence_1 = { 488b05???????? 4833c4 48898424c8020000 488b8424f0020000 }
            // n = 4, score = 100
            //   488b05????????       |                     
            //   4833c4               | dec                 eax
            //   48898424c8020000     | sub                 esp, 0x68
            //   488b8424f0020000     | dec                 eax

        $sequence_2 = { 8b8c2424490000 4869c998040000 488b842400470000 488d8c0884000000 488d9424b0440000 ff15???????? c784244849000004010000 }
            // n = 7, score = 100
            //   8b8c2424490000       | int3                
            //   4869c998040000       | mov                 dl, 1
            //   488b842400470000     | dec                 eax
            //   488d8c0884000000     | mov                 ecx, edi
            //   488d9424b0440000     | dec                 esp
            //   ff15????????         |                     
            //   c784244849000004010000     | lea    ebx, [0xeb1a]

        $sequence_3 = { 488b442420 4883c001 4889442420 8b542448 488b4c2440 }
            // n = 5, score = 100
            //   488b442420           | dec                 eax
            //   4883c001             | lea                 eax, [0x11e83]
            //   4889442420           | dec                 eax
            //   8b542448             | cmp                 ecx, eax
            //   488b4c2440           | dec                 eax

        $sequence_4 = { 4889542410 894c2408 56 57 b868490000 }
            // n = 5, score = 100
            //   4889542410           | dec                 eax
            //   894c2408             | lea                 edx, [esp + 0x260]
            //   56                   | dec                 eax
            //   57                   | mov                 ecx, dword ptr [esp + 0xbf0]
            //   b868490000           | mov                 dword ptr [esp + 0x30], 0

        $sequence_5 = { b801000000 e9???????? 0fb705???????? 83f802 0f85c1000000 8b05???????? 89842418010000 }
            // n = 7, score = 100
            //   b801000000           | jne                 0xf13
            //   e9????????           |                     
            //   0fb705????????       |                     
            //   83f802               | je                  0xf0c
            //   0f85c1000000         | dec                 eax
            //   8b05????????         |                     
            //   89842418010000       | lea                 eax, [esp + 0x40]

        $sequence_6 = { 488d8c0884000000 488d9424b0440000 ff15???????? c784244849000004010000 8b8c2424490000 4869c998040000 488b842400470000 }
            // n = 7, score = 100
            //   488d8c0884000000     | push                edi
            //   488d9424b0440000     | dec                 eax
            //   ff15????????         |                     
            //   c784244849000004010000     | sub    esp, 0x20
            //   8b8c2424490000       | dec                 eax
            //   4869c998040000       | arpl                cx, di
            //   488b842400470000     | cmp                 dword ptr [eax], 0

        $sequence_7 = { 4889842450020000 c744242804010000 448b442428 488d542440 }
            // n = 4, score = 100
            //   4889842450020000     | mov                 eax, 1
            //   c744242804010000     | dec                 eax
            //   448b442428           | cmp                 dword ptr [esp + 0x38], 0
            //   488d542440           | je                  0x4cd

        $sequence_8 = { 4889442420 488b842468090000 4883c002 4889842468090000 ebb5 8b942470090000 }
            // n = 6, score = 100
            //   4889442420           | push                edi
            //   488b842468090000     | dec                 eax
            //   4883c002             | sub                 esp, 0x20
            //   4889842468090000     | dec                 eax
            //   ebb5                 | arpl                cx, bx
            //   8b942470090000       | dec                 eax

        $sequence_9 = { 488b05???????? 4833c4 4889842450010000 c744242000000000 }
            // n = 4, score = 100
            //   488b05????????       |                     
            //   4833c4               | dec                 eax
            //   4889842450010000     | add                 ecx, 0xc
            //   c744242000000000     | dec                 eax

    condition:
        7 of them and filesize < 373760
}