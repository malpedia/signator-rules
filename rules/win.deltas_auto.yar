rule win_deltas_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.deltas."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.deltas"
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
        $sequence_0 = { 33c1 03c5 8b6c242c 8d8410c67e9b28 8bd0 }
            // n = 5, score = 200
            //   33c1                 | xor                 eax, ecx
            //   03c5                 | add                 eax, ebp
            //   8b6c242c             | mov                 ebp, dword ptr [esp + 0x2c]
            //   8d8410c67e9b28       | lea                 eax, [eax + edx + 0x289b7ec6]
            //   8bd0                 | mov                 edx, eax

        $sequence_1 = { f2ae f7d1 49 8d84242c010000 51 52 }
            // n = 6, score = 200
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx
            //   8d84242c010000       | lea                 eax, [esp + 0x12c]
            //   51                   | push                ecx
            //   52                   | push                edx

        $sequence_2 = { 897c2420 ff15???????? 5f 33c0 5e }
            // n = 5, score = 200
            //   897c2420             | mov                 dword ptr [esp + 0x20], edi
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi

        $sequence_3 = { 0bc8 8b442414 03c8 8b442410 8d84012108b449 8bc8 c1e116 }
            // n = 7, score = 200
            //   0bc8                 | or                  ecx, eax
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   03c8                 | add                 ecx, eax
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   8d84012108b449       | lea                 eax, [ecx + eax + 0x49b40821]
            //   8bc8                 | mov                 ecx, eax
            //   c1e116               | shl                 ecx, 0x16

        $sequence_4 = { 8b742410 8b442414 03c6 89442414 8d3418 8b0418 85c0 }
            // n = 7, score = 200
            //   8b742410             | mov                 esi, dword ptr [esp + 0x10]
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   03c6                 | add                 eax, esi
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   8d3418               | lea                 esi, [eax + ebx]
            //   8b0418               | mov                 eax, dword ptr [eax + ebx]
            //   85c0                 | test                eax, eax

        $sequence_5 = { 83c40c 8d842410020000 68???????? 68???????? 50 }
            // n = 5, score = 200
            //   83c40c               | add                 esp, 0xc
            //   8d842410020000       | lea                 eax, [esp + 0x210]
            //   68????????           |                     
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_6 = { 8d8408ed145a45 8bc8 c1e114 c1e80c 0bc8 }
            // n = 5, score = 200
            //   8d8408ed145a45       | lea                 eax, [eax + ecx + 0x455a14ed]
            //   8bc8                 | mov                 ecx, eax
            //   c1e114               | shl                 ecx, 0x14
            //   c1e80c               | shr                 eax, 0xc
            //   0bc8                 | or                  ecx, eax

        $sequence_7 = { c1ee17 0bf0 8bc1 03f2 f7d0 8bde 23c2 }
            // n = 7, score = 200
            //   c1ee17               | shr                 esi, 0x17
            //   0bf0                 | or                  esi, eax
            //   8bc1                 | mov                 eax, ecx
            //   03f2                 | add                 esi, edx
            //   f7d0                 | not                 eax
            //   8bde                 | mov                 ebx, esi
            //   23c2                 | and                 eax, edx

        $sequence_8 = { 85f6 8bf8 7439 85ff 7435 68???????? 56 }
            // n = 7, score = 200
            //   85f6                 | test                esi, esi
            //   8bf8                 | mov                 edi, eax
            //   7439                 | je                  0x3b
            //   85ff                 | test                edi, edi
            //   7435                 | je                  0x37
            //   68????????           |                     
            //   56                   | push                esi

        $sequence_9 = { 8b35???????? 8d442470 50 885c2467 ffd6 8d8c2480000000 8bf8 }
            // n = 7, score = 200
            //   8b35????????         |                     
            //   8d442470             | lea                 eax, [esp + 0x70]
            //   50                   | push                eax
            //   885c2467             | mov                 byte ptr [esp + 0x67], bl
            //   ffd6                 | call                esi
            //   8d8c2480000000       | lea                 ecx, [esp + 0x80]
            //   8bf8                 | mov                 edi, eax

    condition:
        7 of them and filesize < 90112
}