rule win_cohhoc_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.cohhoc."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cohhoc"
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
        $sequence_0 = { f7d1 2bf9 c744244c01000000 8bc1 8bf7 8bfa c784248001000000000000 }
            // n = 7, score = 300
            //   f7d1                 | not                 ecx
            //   2bf9                 | sub                 edi, ecx
            //   c744244c01000000     | mov                 dword ptr [esp + 0x4c], 1
            //   8bc1                 | mov                 eax, ecx
            //   8bf7                 | mov                 esi, edi
            //   8bfa                 | mov                 edi, edx
            //   c784248001000000000000     | mov    dword ptr [esp + 0x180], 0

        $sequence_1 = { 83c418 8bf8 56 ff15???????? 57 e8???????? 57 }
            // n = 7, score = 300
            //   83c418               | add                 esp, 0x18
            //   8bf8                 | mov                 edi, eax
            //   56                   | push                esi
            //   ff15????????         |                     
            //   57                   | push                edi
            //   e8????????           |                     
            //   57                   | push                edi

        $sequence_2 = { 33ff 66897802 c60000 897804 897808 89450c }
            // n = 6, score = 300
            //   33ff                 | xor                 edi, edi
            //   66897802             | mov                 word ptr [eax + 2], di
            //   c60000               | mov                 byte ptr [eax], 0
            //   897804               | mov                 dword ptr [eax + 4], edi
            //   897808               | mov                 dword ptr [eax + 8], edi
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax

        $sequence_3 = { f7d1 2bf9 c68414ac01000000 8bf7 }
            // n = 4, score = 300
            //   f7d1                 | not                 ecx
            //   2bf9                 | sub                 edi, ecx
            //   c68414ac01000000     | mov                 byte ptr [esp + edx + 0x1ac], 0
            //   8bf7                 | mov                 esi, edi

        $sequence_4 = { 8db424e4000000 7407 8db424a4000000 bf???????? 68e8030000 }
            // n = 5, score = 300
            //   8db424e4000000       | lea                 esi, [esp + 0xe4]
            //   7407                 | je                  9
            //   8db424a4000000       | lea                 esi, [esp + 0xa4]
            //   bf????????           |                     
            //   68e8030000           | push                0x3e8

        $sequence_5 = { 894608 81fbff000000 8bf0 7edc 5f }
            // n = 5, score = 300
            //   894608               | mov                 dword ptr [esi + 8], eax
            //   81fbff000000         | cmp                 ebx, 0xff
            //   8bf0                 | mov                 esi, eax
            //   7edc                 | jle                 0xffffffde
            //   5f                   | pop                 edi

        $sequence_6 = { 53 89442414 ff15???????? 55 56 }
            // n = 5, score = 300
            //   53                   | push                ebx
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   ff15????????         |                     
            //   55                   | push                ebp
            //   56                   | push                esi

        $sequence_7 = { b911000000 33c0 8dbc2424010000 8d942424010000 f3ab 8d4c2410 }
            // n = 6, score = 300
            //   b911000000           | mov                 ecx, 0x11
            //   33c0                 | xor                 eax, eax
            //   8dbc2424010000       | lea                 edi, [esp + 0x124]
            //   8d942424010000       | lea                 edx, [esp + 0x124]
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8d4c2410             | lea                 ecx, [esp + 0x10]

        $sequence_8 = { 2bda 81fb003c0000 775f 8bcb 8d3402 8bd1 }
            // n = 6, score = 300
            //   2bda                 | sub                 ebx, edx
            //   81fb003c0000         | cmp                 ebx, 0x3c00
            //   775f                 | ja                  0x61
            //   8bcb                 | mov                 ecx, ebx
            //   8d3402               | lea                 esi, [edx + eax]
            //   8bd1                 | mov                 edx, ecx

        $sequence_9 = { 8808 8b4e04 41 4f }
            // n = 4, score = 300
            //   8808                 | mov                 byte ptr [eax], cl
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   41                   | inc                 ecx
            //   4f                   | dec                 edi

    condition:
        7 of them and filesize < 253952
}