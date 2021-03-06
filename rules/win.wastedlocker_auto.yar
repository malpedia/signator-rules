rule win_wastedlocker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.wastedlocker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wastedlocker"
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
        $sequence_0 = { 7417 8b442408 397004 741f 6a00 50 }
            // n = 6, score = 1000
            //   7417                 | je                  0x19
            //   8b442408             | mov                 eax, dword ptr [esp + 8]
            //   397004               | cmp                 dword ptr [eax + 4], esi
            //   741f                 | je                  0x21
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_1 = { 894de0 8b5718 8955d0 3bc1 740f 8a08 884de7 }
            // n = 7, score = 1000
            //   894de0               | mov                 dword ptr [ebp - 0x20], ecx
            //   8b5718               | mov                 edx, dword ptr [edi + 0x18]
            //   8955d0               | mov                 dword ptr [ebp - 0x30], edx
            //   3bc1                 | cmp                 eax, ecx
            //   740f                 | je                  0x11
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   884de7               | mov                 byte ptr [ebp - 0x19], cl

        $sequence_2 = { 51 ff75fc ff15???????? 57 ff75fc }
            // n = 5, score = 1000
            //   51                   | push                ecx
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff15????????         |                     
            //   57                   | push                edi
            //   ff75fc               | push                dword ptr [ebp - 4]

        $sequence_3 = { 740e 57 53 ff35???????? ff15???????? 5f }
            // n = 6, score = 1000
            //   740e                 | je                  0x10
            //   57                   | push                edi
            //   53                   | push                ebx
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   5f                   | pop                 edi

        $sequence_4 = { 8bdf e8???????? 8bf8 53 6a00 ff35???????? ffd6 }
            // n = 7, score = 1000
            //   8bdf                 | mov                 ebx, edi
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   53                   | push                ebx
            //   6a00                 | push                0
            //   ff35????????         |                     
            //   ffd6                 | call                esi

        $sequence_5 = { 8b45f0 85c0 740f 837f1c00 }
            // n = 4, score = 1000
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   85c0                 | test                eax, eax
            //   740f                 | je                  0x11
            //   837f1c00             | cmp                 dword ptr [edi + 0x1c], 0

        $sequence_6 = { 741a ff75e8 6a00 ff35???????? ff15???????? eb07 c745f801000000 }
            // n = 7, score = 1000
            //   741a                 | je                  0x1c
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   6a00                 | push                0
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   eb07                 | jmp                 9
            //   c745f801000000       | mov                 dword ptr [ebp - 8], 1

        $sequence_7 = { 6a00 ff35???????? 894dfc 33f9 }
            // n = 4, score = 1000
            //   6a00                 | push                0
            //   ff35????????         |                     
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   33f9                 | xor                 edi, ecx

        $sequence_8 = { 3b461c 720d 7705 3b4e18 7606 }
            // n = 5, score = 1000
            //   3b461c               | cmp                 eax, dword ptr [esi + 0x1c]
            //   720d                 | jb                  0xf
            //   7705                 | ja                  7
            //   3b4e18               | cmp                 ecx, dword ptr [esi + 0x18]
            //   7606                 | jbe                 8

        $sequence_9 = { 743a 57 53 ffd6 85c0 }
            // n = 5, score = 1000
            //   743a                 | je                  0x3c
            //   57                   | push                edi
            //   53                   | push                ebx
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax

    condition:
        7 of them and filesize < 147456
}