rule win_zxxz_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.zxxz."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zxxz"
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
        $sequence_0 = { 68fa000000 52 ff15???????? 83c40c }
            // n = 4, score = 100
            //   68fa000000           | push                0xfa
            //   52                   | push                edx
            //   ff15????????         |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_1 = { 33f6 84c0 7418 8d89315c4000 }
            // n = 4, score = 100
            //   33f6                 | xor                 esi, esi
            //   84c0                 | test                al, al
            //   7418                 | je                  0x1a
            //   8d89315c4000         | lea                 ecx, [ecx + 0x405c31]

        $sequence_2 = { 83c404 68983a0000 ffd6 a1???????? 40 3de1000000 a3???????? }
            // n = 7, score = 100
            //   83c404               | add                 esp, 4
            //   68983a0000           | push                0x3a98
            //   ffd6                 | call                esi
            //   a1????????           |                     
            //   40                   | inc                 eax
            //   3de1000000           | cmp                 eax, 0xe1
            //   a3????????           |                     

        $sequence_3 = { 50 8d44244c 64a300000000 8b6c245c 83ec1c }
            // n = 5, score = 100
            //   50                   | push                eax
            //   8d44244c             | lea                 eax, [esp + 0x4c]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8b6c245c             | mov                 ebp, dword ptr [esp + 0x5c]
            //   83ec1c               | sub                 esp, 0x1c

        $sequence_4 = { 57 52 ffd3 83c408 85c0 752f 8d442408 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   52                   | push                edx
            //   ffd3                 | call                ebx
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   752f                 | jne                 0x31
            //   8d442408             | lea                 eax, [esp + 8]

        $sequence_5 = { b90b000000 be???????? 8dbc24a0010000 f3a5 68cc000000 8d9424d2010000 }
            // n = 6, score = 100
            //   b90b000000           | mov                 ecx, 0xb
            //   be????????           |                     
            //   8dbc24a0010000       | lea                 edi, [esp + 0x1a0]
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   68cc000000           | push                0xcc
            //   8d9424d2010000       | lea                 edx, [esp + 0x1d2]

        $sequence_6 = { e8???????? 83c40c 68???????? bb???????? ba???????? }
            // n = 5, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   68????????           |                     
            //   bb????????           |                     
            //   ba????????           |                     

        $sequence_7 = { 56 8b35???????? 6a6b 50 c744241030000000 }
            // n = 5, score = 100
            //   56                   | push                esi
            //   8b35????????         |                     
            //   6a6b                 | push                0x6b
            //   50                   | push                eax
            //   c744241030000000     | mov                 dword ptr [esp + 0x10], 0x30

        $sequence_8 = { 8d4804 e8???????? 8b8c2410010000 5f }
            // n = 4, score = 100
            //   8d4804               | lea                 ecx, [eax + 4]
            //   e8????????           |                     
            //   8b8c2410010000       | mov                 ecx, dword ptr [esp + 0x110]
            //   5f                   | pop                 edi

        $sequence_9 = { 68fa000000 50 ffd5 83c40c 68???????? 8d4c2414 }
            // n = 6, score = 100
            //   68fa000000           | push                0xfa
            //   50                   | push                eax
            //   ffd5                 | call                ebp
            //   83c40c               | add                 esp, 0xc
            //   68????????           |                     
            //   8d4c2414             | lea                 ecx, [esp + 0x14]

    condition:
        7 of them and filesize < 4142080
}