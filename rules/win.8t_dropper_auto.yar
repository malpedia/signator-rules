rule win_8t_dropper_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.8t_dropper."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.8t_dropper"
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
        $sequence_0 = { 50 52 6801000080 ff15???????? bf???????? 83c9ff }
            // n = 6, score = 200
            //   50                   | push                eax
            //   52                   | push                edx
            //   6801000080           | push                0x80000001
            //   ff15????????         |                     
            //   bf????????           |                     
            //   83c9ff               | or                  ecx, 0xffffffff

        $sequence_1 = { 85f6 741b 56 6800700000 6a01 }
            // n = 5, score = 200
            //   85f6                 | test                esi, esi
            //   741b                 | je                  0x1d
            //   56                   | push                esi
            //   6800700000           | push                0x7000
            //   6a01                 | push                1

        $sequence_2 = { 8bc6 5f 5e 5b c9 c3 ff35???????? }
            // n = 7, score = 200
            //   8bc6                 | mov                 eax, esi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   c3                   | ret                 
            //   ff35????????         |                     

        $sequence_3 = { 83c408 85f6 741b 56 6800700000 6a01 68???????? }
            // n = 7, score = 200
            //   83c408               | add                 esp, 8
            //   85f6                 | test                esi, esi
            //   741b                 | je                  0x1d
            //   56                   | push                esi
            //   6800700000           | push                0x7000
            //   6a01                 | push                1
            //   68????????           |                     

        $sequence_4 = { 52 68???????? ff15???????? 8d842410010000 68???????? 50 }
            // n = 6, score = 200
            //   52                   | push                edx
            //   68????????           |                     
            //   ff15????????         |                     
            //   8d842410010000       | lea                 eax, [esp + 0x110]
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_5 = { ff74240c e8???????? 83c40c c3 8b442408 83f801 0f8588000000 }
            // n = 7, score = 200
            //   ff74240c             | push                dword ptr [esp + 0xc]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   c3                   | ret                 
            //   8b442408             | mov                 eax, dword ptr [esp + 8]
            //   83f801               | cmp                 eax, 1
            //   0f8588000000         | jne                 0x8e

        $sequence_6 = { 81ec0c020000 56 57 b940000000 33c0 8d7c240d }
            // n = 6, score = 200
            //   81ec0c020000         | sub                 esp, 0x20c
            //   56                   | push                esi
            //   57                   | push                edi
            //   b940000000           | mov                 ecx, 0x40
            //   33c0                 | xor                 eax, eax
            //   8d7c240d             | lea                 edi, [esp + 0xd]

        $sequence_7 = { 6801000080 ff15???????? bf???????? 83c9ff 33c0 f2ae }
            // n = 6, score = 200
            //   6801000080           | push                0x80000001
            //   ff15????????         |                     
            //   bf????????           |                     
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]

        $sequence_8 = { 683f000f00 50 52 6801000080 ff15???????? bf???????? 83c9ff }
            // n = 7, score = 200
            //   683f000f00           | push                0xf003f
            //   50                   | push                eax
            //   52                   | push                edx
            //   6801000080           | push                0x80000001
            //   ff15????????         |                     
            //   bf????????           |                     
            //   83c9ff               | or                  ecx, 0xffffffff

        $sequence_9 = { f2ae f7d1 49 c6440c0c52 c6440c0d75 c6440c0e6e 8d4c2408 }
            // n = 7, score = 200
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx
            //   c6440c0c52           | mov                 byte ptr [esp + ecx + 0xc], 0x52
            //   c6440c0d75           | mov                 byte ptr [esp + ecx + 0xd], 0x75
            //   c6440c0e6e           | mov                 byte ptr [esp + ecx + 0xe], 0x6e
            //   8d4c2408             | lea                 ecx, [esp + 8]

    condition:
        7 of them and filesize < 147456
}