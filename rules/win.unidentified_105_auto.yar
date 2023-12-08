rule win_unidentified_105_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.unidentified_105."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_105"
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
        $sequence_0 = { 85c0 0f95c0 84c0 742c }
            // n = 4, score = 200
            //   85c0                 | test                eax, eax
            //   0f95c0               | setne               al
            //   84c0                 | test                al, al
            //   742c                 | je                  0x2e

        $sequence_1 = { 8bf8 8d4f02 b856555555 f7e9 8bc2 c1e81f 03c2 }
            // n = 7, score = 200
            //   8bf8                 | mov                 edi, eax
            //   8d4f02               | lea                 ecx, [edi + 2]
            //   b856555555           | mov                 eax, 0x55555556
            //   f7e9                 | imul                ecx
            //   8bc2                 | mov                 eax, edx
            //   c1e81f               | shr                 eax, 0x1f
            //   03c2                 | add                 eax, edx

        $sequence_2 = { 6a00 8d8dd0feffff 51 8d95fcfeffff }
            // n = 4, score = 200
            //   6a00                 | push                0
            //   8d8dd0feffff         | lea                 ecx, [ebp - 0x130]
            //   51                   | push                ecx
            //   8d95fcfeffff         | lea                 edx, [ebp - 0x104]

        $sequence_3 = { 8d8d94feffff 51 6800000010 50 52 ff15???????? 85c0 }
            // n = 7, score = 200
            //   8d8d94feffff         | lea                 ecx, [ebp - 0x16c]
            //   51                   | push                ecx
            //   6800000010           | push                0x10000000
            //   50                   | push                eax
            //   52                   | push                edx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_4 = { e8???????? 83c404 50 e8???????? a1???????? 6800020000 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   50                   | push                eax
            //   e8????????           |                     
            //   a1????????           |                     
            //   6800020000           | push                0x200

        $sequence_5 = { 83f8ff 7459 8d9424a0010000 52 }
            // n = 4, score = 200
            //   83f8ff               | cmp                 eax, -1
            //   7459                 | je                  0x5b
            //   8d9424a0010000       | lea                 edx, [esp + 0x1a0]
            //   52                   | push                edx

        $sequence_6 = { 68???????? 56 e8???????? 8bc6 83c454 }
            // n = 5, score = 200
            //   68????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   8bc6                 | mov                 eax, esi
            //   83c454               | add                 esp, 0x54

        $sequence_7 = { 8bf8 8d4f02 b856555555 f7e9 8bc2 }
            // n = 5, score = 200
            //   8bf8                 | mov                 edi, eax
            //   8d4f02               | lea                 ecx, [edi + 2]
            //   b856555555           | mov                 eax, 0x55555556
            //   f7e9                 | imul                ecx
            //   8bc2                 | mov                 eax, edx

        $sequence_8 = { 8b3d???????? 8d45e4 50 33f6 }
            // n = 4, score = 200
            //   8b3d????????         |                     
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   50                   | push                eax
            //   33f6                 | xor                 esi, esi

        $sequence_9 = { 6800100000 8d85f8efffff 50 51 }
            // n = 4, score = 200
            //   6800100000           | push                0x1000
            //   8d85f8efffff         | lea                 eax, [ebp - 0x1008]
            //   50                   | push                eax
            //   51                   | push                ecx

    condition:
        7 of them and filesize < 253952
}