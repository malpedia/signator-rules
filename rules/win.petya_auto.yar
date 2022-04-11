rule win_petya_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.petya."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.petya"
        malpedia_rule_date = "20220405"
        malpedia_hash = "ecd38294bd47d5589be5cd5490dc8bb4804afc2a"
        malpedia_version = ""
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
        $sequence_0 = { 8bce e8???????? c7461001000000 33c0 5e }
            // n = 5, score = 600
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   c7461001000000       | mov                 dword ptr [esi + 0x10], 1
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi

        $sequence_1 = { c1e60e c1e017 33ff 0bf9 c1eb09 8b4c2424 }
            // n = 6, score = 600
            //   c1e60e               | shl                 esi, 0xe
            //   c1e017               | shl                 eax, 0x17
            //   33ff                 | xor                 edi, edi
            //   0bf9                 | or                  edi, ecx
            //   c1eb09               | shr                 ebx, 9
            //   8b4c2424             | mov                 ecx, dword ptr [esp + 0x24]

        $sequence_2 = { 4e 75f5 46 3bf2 53 }
            // n = 5, score = 600
            //   4e                   | dec                 esi
            //   75f5                 | jne                 0xfffffff7
            //   46                   | inc                 esi
            //   3bf2                 | cmp                 esi, edx
            //   53                   | push                ebx

        $sequence_3 = { 56 83c050 03c7 53 50 }
            // n = 5, score = 600
            //   56                   | push                esi
            //   83c050               | add                 eax, 0x50
            //   03c7                 | add                 eax, edi
            //   53                   | push                ebx
            //   50                   | push                eax

        $sequence_4 = { c1e303 0facc110 897c2424 c1e810 8bc2 884c242d 0facf008 }
            // n = 7, score = 600
            //   c1e303               | shl                 ebx, 3
            //   0facc110             | shrd                ecx, eax, 0x10
            //   897c2424             | mov                 dword ptr [esp + 0x24], edi
            //   c1e810               | shr                 eax, 0x10
            //   8bc2                 | mov                 eax, edx
            //   884c242d             | mov                 byte ptr [esp + 0x2d], cl
            //   0facf008             | shrd                eax, esi, 8

        $sequence_5 = { 0f42f2 6a04 56 e8???????? 8bd8 }
            // n = 5, score = 600
            //   0f42f2               | cmovb               esi, edx
            //   6a04                 | push                4
            //   56                   | push                esi
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax

        $sequence_6 = { 47 83c324 3b7e78 72ed 5b ff7674 }
            // n = 6, score = 600
            //   47                   | inc                 edi
            //   83c324               | add                 ebx, 0x24
            //   3b7e78               | cmp                 edi, dword ptr [esi + 0x78]
            //   72ed                 | jb                  0xffffffef
            //   5b                   | pop                 ebx
            //   ff7674               | push                dword ptr [esi + 0x74]

        $sequence_7 = { 0fa4c117 8bda c1e60e c1e017 33ff 0bf9 }
            // n = 6, score = 600
            //   0fa4c117             | shld                ecx, eax, 0x17
            //   8bda                 | mov                 ebx, edx
            //   c1e60e               | shl                 esi, 0xe
            //   c1e017               | shl                 eax, 0x17
            //   33ff                 | xor                 edi, edi
            //   0bf9                 | or                  edi, ecx

        $sequence_8 = { ff15???????? 50 ff15???????? 8d4df8 }
            // n = 4, score = 600
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d4df8               | lea                 ecx, dword ptr [ebp - 8]

        $sequence_9 = { 56 83c050 03c7 53 50 e8???????? }
            // n = 6, score = 600
            //   56                   | push                esi
            //   83c050               | add                 eax, 0x50
            //   03c7                 | add                 eax, edi
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     

    condition:
        7 of them and filesize < 229376
}