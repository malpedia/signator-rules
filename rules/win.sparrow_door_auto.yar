rule win_sparrow_door_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.sparrow_door."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sparrow_door"
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
        $sequence_0 = { 6a00 6a00 68bb010000 50 51 ff15???????? 89442414 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   68bb010000           | push                0x1bb
            //   50                   | push                eax
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   89442414             | mov                 dword ptr [esp + 0x14], eax

        $sequence_1 = { 53 ff15???????? 6804010000 8d842428020000 50 53 ffd6 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   6804010000           | push                0x104
            //   8d842428020000       | lea                 eax, [esp + 0x228]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   ffd6                 | call                esi

        $sequence_2 = { 57 e8???????? 8b8c24c0060000 83c404 }
            // n = 4, score = 100
            //   57                   | push                edi
            //   e8????????           |                     
            //   8b8c24c0060000       | mov                 ecx, dword ptr [esp + 0x6c0]
            //   83c404               | add                 esp, 4

        $sequence_3 = { e8???????? 83c404 57 e8???????? 8b7c2420 83c404 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   57                   | push                edi
            //   e8????????           |                     
            //   8b7c2420             | mov                 edi, dword ptr [esp + 0x20]
            //   83c404               | add                 esp, 4

        $sequence_4 = { 7453 8b54242c 8b442418 8d4c2414 51 53 52 }
            // n = 7, score = 100
            //   7453                 | je                  0x55
            //   8b54242c             | mov                 edx, dword ptr [esp + 0x2c]
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]
            //   8d4c2414             | lea                 ecx, [esp + 0x14]
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   52                   | push                edx

        $sequence_5 = { 55 6a65 68???????? 56 ff15???????? 8b842448200000 8b4c2430 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   6a65                 | push                0x65
            //   68????????           |                     
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8b842448200000       | mov                 eax, dword ptr [esp + 0x2048]
            //   8b4c2430             | mov                 ecx, dword ptr [esp + 0x30]

        $sequence_6 = { 8b44241c 83c404 50 eba8 85ed 7409 }
            // n = 6, score = 100
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   83c404               | add                 esp, 4
            //   50                   | push                eax
            //   eba8                 | jmp                 0xffffffaa
            //   85ed                 | test                ebp, ebp
            //   7409                 | je                  0xb

        $sequence_7 = { 53 57 ff15???????? 8bf0 85f6 7524 }
            // n = 6, score = 100
            //   53                   | push                ebx
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   7524                 | jne                 0x26

        $sequence_8 = { 0fb754244c 6803010000 6689442440 8d8424ad030000 6a00 50 66894c2442 }
            // n = 7, score = 100
            //   0fb754244c           | movzx               edx, word ptr [esp + 0x4c]
            //   6803010000           | push                0x103
            //   6689442440           | mov                 word ptr [esp + 0x40], ax
            //   8d8424ad030000       | lea                 eax, [esp + 0x3ad]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   66894c2442           | mov                 word ptr [esp + 0x42], cx

        $sequence_9 = { 0b742434 8b742420 0f851efeffff 57 e8???????? }
            // n = 5, score = 100
            //   0b742434             | or                  esi, dword ptr [esp + 0x34]
            //   8b742420             | mov                 esi, dword ptr [esp + 0x20]
            //   0f851efeffff         | jne                 0xfffffe24
            //   57                   | push                edi
            //   e8????????           |                     

    condition:
        7 of them and filesize < 155648
}