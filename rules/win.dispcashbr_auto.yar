rule win_dispcashbr_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.dispcashbr."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dispcashbr"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
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
        $sequence_0 = { e8???????? 83ec08 c7442408ceffffff c7442404???????? }
            // n = 4, score = 200
            //   e8????????           |                     
            //   83ec08               | sub                 esp, 8
            //   c7442408ceffffff     | mov                 dword ptr [esp + 8], 0xffffffce
            //   c7442404????????     |                     

        $sequence_1 = { e8???????? 83ec08 c7442408eaffffff c7442404???????? }
            // n = 4, score = 200
            //   e8????????           |                     
            //   83ec08               | sub                 esp, 8
            //   c7442408eaffffff     | mov                 dword ptr [esp + 8], 0xffffffea
            //   c7442404????????     |                     

        $sequence_2 = { e8???????? 83ec08 c7442408ceffffff c7442404???????? a1???????? 83c020 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   83ec08               | sub                 esp, 8
            //   c7442408ceffffff     | mov                 dword ptr [esp + 8], 0xffffffce
            //   c7442404????????     |                     
            //   a1????????           |                     
            //   83c020               | add                 eax, 0x20

        $sequence_3 = { a1???????? 83c020 890424 e8???????? eb45 c70424f5ffffff e8???????? }
            // n = 7, score = 200
            //   a1????????           |                     
            //   83c020               | add                 eax, 0x20
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   eb45                 | jmp                 0x47
            //   c70424f5ffffff       | mov                 dword ptr [esp], 0xfffffff5
            //   e8????????           |                     

        $sequence_4 = { 83ec08 c7442408f2ffffff c7442404???????? a1???????? 83c020 890424 e8???????? }
            // n = 7, score = 200
            //   83ec08               | sub                 esp, 8
            //   c7442408f2ffffff     | mov                 dword ptr [esp + 8], 0xfffffff2
            //   c7442404????????     |                     
            //   a1????????           |                     
            //   83c020               | add                 eax, 0x20
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     

        $sequence_5 = { 83ec08 c7442408d9ffffff c7442404???????? a1???????? 83c020 890424 }
            // n = 6, score = 200
            //   83ec08               | sub                 esp, 8
            //   c7442408d9ffffff     | mov                 dword ptr [esp + 8], 0xffffffd9
            //   c7442404????????     |                     
            //   a1????????           |                     
            //   83c020               | add                 eax, 0x20
            //   890424               | mov                 dword ptr [esp], eax

        $sequence_6 = { 890424 e8???????? 83ec08 c7442408d7ffffff }
            // n = 4, score = 200
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   83ec08               | sub                 esp, 8
            //   c7442408d7ffffff     | mov                 dword ptr [esp + 8], 0xffffffd7

        $sequence_7 = { 890424 e8???????? 83ec08 c7442408c9ffffff c7442404???????? }
            // n = 5, score = 200
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   83ec08               | sub                 esp, 8
            //   c7442408c9ffffff     | mov                 dword ptr [esp + 8], 0xffffffc9
            //   c7442404????????     |                     

        $sequence_8 = { 83ec04 c744240404000000 890424 e8???????? 83ec08 c7442408f2ffffff c7442404???????? }
            // n = 7, score = 200
            //   83ec04               | sub                 esp, 4
            //   c744240404000000     | mov                 dword ptr [esp + 4], 4
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   83ec08               | sub                 esp, 8
            //   c7442408f2ffffff     | mov                 dword ptr [esp + 8], 0xfffffff2
            //   c7442404????????     |                     

        $sequence_9 = { c70424f5ffffff e8???????? 83ec04 c744240404000000 }
            // n = 4, score = 200
            //   c70424f5ffffff       | mov                 dword ptr [esp], 0xfffffff5
            //   e8????????           |                     
            //   83ec04               | sub                 esp, 4
            //   c744240404000000     | mov                 dword ptr [esp + 4], 4

    condition:
        7 of them and filesize < 123904
}