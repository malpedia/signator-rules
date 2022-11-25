rule win_isspace_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.isspace."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.isspace"
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
        $sequence_0 = { 8dbc2420010000 f2ae 33c9 6690 }
            // n = 4, score = 200
            //   8dbc2420010000       | lea                 edi, [esp + 0x120]
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   33c9                 | xor                 ecx, ecx
            //   6690                 | nop                 

        $sequence_1 = { 83ec38 48 8d0d89050000 e8???????? 44 8b1d???????? 44 }
            // n = 7, score = 200
            //   83ec38               | sub                 esp, 0x38
            //   48                   | dec                 eax
            //   8d0d89050000         | lea                 ecx, [0x589]
            //   e8????????           |                     
            //   44                   | inc                 esp
            //   8b1d????????         |                     
            //   44                   | inc                 esp

        $sequence_2 = { c68424f300000073 c68424f400000073 c68424f500000041 40 88b424f6000000 ff15???????? }
            // n = 6, score = 200
            //   c68424f300000073     | mov                 byte ptr [esp + 0xf3], 0x73
            //   c68424f400000073     | mov                 byte ptr [esp + 0xf4], 0x73
            //   c68424f500000041     | mov                 byte ptr [esp + 0xf5], 0x41
            //   40                   | inc                 eax
            //   88b424f6000000       | mov                 byte ptr [esp + 0xf6], dh
            //   ff15????????         |                     

        $sequence_3 = { 8d0daf080000 ff15???????? 833d????????00 750a }
            // n = 4, score = 200
            //   8d0daf080000         | lea                 ecx, [0x8af]
            //   ff15????????         |                     
            //   833d????????00       |                     
            //   750a                 | jne                 0xc

        $sequence_4 = { 48 8d0d370f0000 c68424e800000043 c68424e900000072 c68424ea00000065 c68424eb00000061 c68424ec00000074 }
            // n = 7, score = 200
            //   48                   | dec                 eax
            //   8d0d370f0000         | lea                 ecx, [0xf37]
            //   c68424e800000043     | mov                 byte ptr [esp + 0xe8], 0x43
            //   c68424e900000072     | mov                 byte ptr [esp + 0xe9], 0x72
            //   c68424ea00000065     | mov                 byte ptr [esp + 0xea], 0x65
            //   c68424eb00000061     | mov                 byte ptr [esp + 0xeb], 0x61
            //   c68424ec00000074     | mov                 byte ptr [esp + 0xec], 0x74

        $sequence_5 = { 48 83c9ff 33c0 48 8d3dc10f0000 f2ae }
            // n = 6, score = 200
            //   48                   | dec                 eax
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   48                   | dec                 eax
            //   8d3dc10f0000         | lea                 edi, [0xfc1]
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]

        $sequence_6 = { b801000000 e8???????? b9e8030000 ff15???????? }
            // n = 4, score = 200
            //   b801000000           | mov                 eax, 1
            //   e8????????           |                     
            //   b9e8030000           | mov                 ecx, 0x3e8
            //   ff15????????         |                     

        $sequence_7 = { 8905???????? b901000000 e8???????? 33c9 ff15???????? 48 8d0daf080000 }
            // n = 7, score = 200
            //   8905????????         |                     
            //   b901000000           | mov                 ecx, 1
            //   e8????????           |                     
            //   33c9                 | xor                 ecx, ecx
            //   ff15????????         |                     
            //   48                   | dec                 eax
            //   8d0daf080000         | lea                 ecx, [0x8af]

    condition:
        7 of them and filesize < 434176
}