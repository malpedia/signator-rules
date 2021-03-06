rule win_crenufs_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.crenufs."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crenufs"
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
        $sequence_0 = { 8b542410 8d4c241c 6a00 51 52 53 56 }
            // n = 7, score = 200
            //   8b542410             | mov                 edx, dword ptr [esp + 0x10]
            //   8d4c241c             | lea                 ecx, [esp + 0x1c]
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   52                   | push                edx
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_1 = { 894508 bbff030000 3b01 7435 8d85dcfbffff 53 }
            // n = 6, score = 200
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   bbff030000           | mov                 ebx, 0x3ff
            //   3b01                 | cmp                 eax, dword ptr [ecx]
            //   7435                 | je                  0x37
            //   8d85dcfbffff         | lea                 eax, [ebp - 0x424]
            //   53                   | push                ebx

        $sequence_2 = { f2ae f7d1 49 807c31ff2f 744d bf???????? 83c9ff }
            // n = 7, score = 200
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx
            //   807c31ff2f           | cmp                 byte ptr [ecx + esi - 1], 0x2f
            //   744d                 | je                  0x4f
            //   bf????????           |                     
            //   83c9ff               | or                  ecx, 0xffffffff

        $sequence_3 = { 8d4de0 ff15???????? 6a01 68???????? 8d8588feffff 68ff000000 50 }
            // n = 7, score = 200
            //   8d4de0               | lea                 ecx, [ebp - 0x20]
            //   ff15????????         |                     
            //   6a01                 | push                1
            //   68????????           |                     
            //   8d8588feffff         | lea                 eax, [ebp - 0x178]
            //   68ff000000           | push                0xff
            //   50                   | push                eax

        $sequence_4 = { e8???????? 8b4c2428 89442414 3bc1 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   8b4c2428             | mov                 ecx, dword ptr [esp + 0x28]
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   3bc1                 | cmp                 eax, ecx

        $sequence_5 = { 52 8d7e58 6a04 57 50 ffd5 }
            // n = 6, score = 200
            //   52                   | push                edx
            //   8d7e58               | lea                 edi, [esi + 0x58]
            //   6a04                 | push                4
            //   57                   | push                edi
            //   50                   | push                eax
            //   ffd5                 | call                ebp

        $sequence_6 = { 3bc1 7214 8b6c2420 896e08 8b4704 3b7008 }
            // n = 6, score = 200
            //   3bc1                 | cmp                 eax, ecx
            //   7214                 | jb                  0x16
            //   8b6c2420             | mov                 ebp, dword ptr [esp + 0x20]
            //   896e08               | mov                 dword ptr [esi + 8], ebp
            //   8b4704               | mov                 eax, dword ptr [edi + 4]
            //   3b7008               | cmp                 esi, dword ptr [eax + 8]

        $sequence_7 = { 8bd0 8d4c241c 56 42 }
            // n = 4, score = 200
            //   8bd0                 | mov                 edx, eax
            //   8d4c241c             | lea                 ecx, [esp + 0x1c]
            //   56                   | push                esi
            //   42                   | inc                 edx

        $sequence_8 = { 8d4e58 6a04 51 52 ffd7 8b5604 8d442408 }
            // n = 7, score = 200
            //   8d4e58               | lea                 ecx, [esi + 0x58]
            //   6a04                 | push                4
            //   51                   | push                ecx
            //   52                   | push                edx
            //   ffd7                 | call                edi
            //   8b5604               | mov                 edx, dword ptr [esi + 4]
            //   8d442408             | lea                 eax, [esp + 8]

        $sequence_9 = { 8b4c2448 b800000001 49 3bf9 7509 8b4514 }
            // n = 6, score = 200
            //   8b4c2448             | mov                 ecx, dword ptr [esp + 0x48]
            //   b800000001           | mov                 eax, 0x1000000
            //   49                   | dec                 ecx
            //   3bf9                 | cmp                 edi, ecx
            //   7509                 | jne                 0xb
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]

    condition:
        7 of them and filesize < 106496
}