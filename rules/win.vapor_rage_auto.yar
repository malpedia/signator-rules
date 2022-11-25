rule win_vapor_rage_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.vapor_rage."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vapor_rage"
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
        $sequence_0 = { 6892390000 6829090000 e8???????? 83c408 894588 6a37 }
            // n = 6, score = 100
            //   6892390000           | push                0x3992
            //   6829090000           | push                0x929
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   894588               | mov                 dword ptr [ebp - 0x78], eax
            //   6a37                 | push                0x37

        $sequence_1 = { 8bec 6874cb260e e8???????? 8d642404 b902000000 49 }
            // n = 6, score = 100
            //   8bec                 | mov                 ebp, esp
            //   6874cb260e           | push                0xe26cb74
            //   e8????????           |                     
            //   8d642404             | lea                 esp, [esp + 4]
            //   b902000000           | mov                 ecx, 2
            //   49                   | dec                 ecx

        $sequence_2 = { 8d642404 8be5 5d c3 55 8bec 689e7c3065 }
            // n = 7, score = 100
            //   8d642404             | lea                 esp, [esp + 4]
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   689e7c3065           | push                0x65307c9e

        $sequence_3 = { 8b35???????? 85f6 7420 6bc618 57 8db878010210 57 }
            // n = 7, score = 100
            //   8b35????????         |                     
            //   85f6                 | test                esi, esi
            //   7420                 | je                  0x22
            //   6bc618               | imul                eax, esi, 0x18
            //   57                   | push                edi
            //   8db878010210         | lea                 edi, [eax + 0x10020178]
            //   57                   | push                edi

        $sequence_4 = { 8bec 6827fdb4ff e8???????? 8d642404 b906000000 49 ff748d08 }
            // n = 7, score = 100
            //   8bec                 | mov                 ebp, esp
            //   6827fdb4ff           | push                0xffb4fd27
            //   e8????????           |                     
            //   8d642404             | lea                 esp, [esp + 4]
            //   b906000000           | mov                 ecx, 6
            //   49                   | dec                 ecx
            //   ff748d08             | push                dword ptr [ebp + ecx*4 + 8]

        $sequence_5 = { 55 8bec 68ab76a7eb e8???????? }
            // n = 4, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   68ab76a7eb           | push                0xeba776ab
            //   e8????????           |                     

        $sequence_6 = { 680b452802 e8???????? 8d642404 b902000000 49 }
            // n = 5, score = 100
            //   680b452802           | push                0x228450b
            //   e8????????           |                     
            //   8d642404             | lea                 esp, [esp + 4]
            //   b902000000           | mov                 ecx, 2
            //   49                   | dec                 ecx

        $sequence_7 = { 52 ff15???????? 8945e8 837de800 7479 8b45e0 50 }
            // n = 7, score = 100
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   837de800             | cmp                 dword ptr [ebp - 0x18], 0
            //   7479                 | je                  0x7b
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   50                   | push                eax

        $sequence_8 = { 55 8bec 68d70b410a e8???????? 8d642404 b908000000 49 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   68d70b410a           | push                0xa410bd7
            //   e8????????           |                     
            //   8d642404             | lea                 esp, [esp + 4]
            //   b908000000           | mov                 ecx, 8
            //   49                   | dec                 ecx

        $sequence_9 = { 8b4df0 8b55f4 035124 8955b8 }
            // n = 4, score = 100
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   035124               | add                 edx, dword ptr [ecx + 0x24]
            //   8955b8               | mov                 dword ptr [ebp - 0x48], edx

    condition:
        7 of them and filesize < 296960
}