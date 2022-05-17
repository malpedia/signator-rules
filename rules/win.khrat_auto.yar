rule win_khrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.khrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.khrat"
        malpedia_rule_date = "20220513"
        malpedia_hash = "7f4b2229e6ae614d86d74917f6d5b41890e62a26"
        malpedia_version = "20220516"
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
        $sequence_0 = { 50 e8???????? 6a00 51 8d85c0fbffff }
            // n = 5, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   8d85c0fbffff         | lea                 eax, [ebp - 0x440]

        $sequence_1 = { e8???????? c705????????01000000 eb1b ff35???????? e8???????? b900003000 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   c705????????01000000     |     
            //   eb1b                 | jmp                 0x1d
            //   ff35????????         |                     
            //   e8????????           |                     
            //   b900003000           | mov                 ecx, 0x300000

        $sequence_2 = { 8d85fcfeffff 50 e8???????? 83f8ff 7445 }
            // n = 5, score = 100
            //   8d85fcfeffff         | lea                 eax, [ebp - 0x104]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83f8ff               | cmp                 eax, -1
            //   7445                 | je                  0x47

        $sequence_3 = { e8???????? 6a00 51 8d85a0fbffff 50 ff35???????? e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   8d85a0fbffff         | lea                 eax, [ebp - 0x460]
            //   50                   | push                eax
            //   ff35????????         |                     
            //   e8????????           |                     

        $sequence_4 = { 6a00 8d85fcfaffff 50 8d85fcfeffff 50 }
            // n = 5, score = 100
            //   6a00                 | push                0
            //   8d85fcfaffff         | lea                 eax, [ebp - 0x504]
            //   50                   | push                eax
            //   8d85fcfeffff         | lea                 eax, [ebp - 0x104]
            //   50                   | push                eax

        $sequence_5 = { 8d45e0 50 68???????? e8???????? c705????????01000000 eb1b }
            // n = 6, score = 100
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   50                   | push                eax
            //   68????????           |                     
            //   e8????????           |                     
            //   c705????????01000000     |     
            //   eb1b                 | jmp                 0x1d

        $sequence_6 = { ffb5b8fbffff e8???????? ffb5bcfbffff 6a00 e8???????? c60300 c64301c4 }
            // n = 7, score = 100
            //   ffb5b8fbffff         | push                dword ptr [ebp - 0x448]
            //   e8????????           |                     
            //   ffb5bcfbffff         | push                dword ptr [ebp - 0x444]
            //   6a00                 | push                0
            //   e8????????           |                     
            //   c60300               | mov                 byte ptr [ebx], 0
            //   c64301c4             | mov                 byte ptr [ebx + 1], 0xc4

        $sequence_7 = { eb59 66c743040000 6808020000 8d85f8fdffff 50 53 }
            // n = 6, score = 100
            //   eb59                 | jmp                 0x5b
            //   66c743040000         | mov                 word ptr [ebx + 4], 0
            //   6808020000           | push                0x208
            //   8d85f8fdffff         | lea                 eax, [ebp - 0x208]
            //   50                   | push                eax
            //   53                   | push                ebx

        $sequence_8 = { 8d8500fdffff 50 e8???????? 8d8500feffff 50 }
            // n = 5, score = 100
            //   8d8500fdffff         | lea                 eax, [ebp - 0x300]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d8500feffff         | lea                 eax, [ebp - 0x200]
            //   50                   | push                eax

        $sequence_9 = { 56 68ff000000 6a01 e8???????? 8b4d0c }
            // n = 5, score = 100
            //   56                   | push                esi
            //   68ff000000           | push                0xff
            //   6a01                 | push                1
            //   e8????????           |                     
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]

    condition:
        7 of them and filesize < 57344
}