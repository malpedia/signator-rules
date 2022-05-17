rule win_parallax_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.parallax."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.parallax"
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
        $sequence_0 = { ff96fc000000 6a04 68???????? 6a0a 68???????? e8???????? 6a04 }
            // n = 7, score = 200
            //   ff96fc000000         | call                dword ptr [esi + 0xfc]
            //   6a04                 | push                4
            //   68????????           |                     
            //   6a0a                 | push                0xa
            //   68????????           |                     
            //   e8????????           |                     
            //   6a04                 | push                4

        $sequence_1 = { 8b7d08 c7870c01000000000000 8b7d08 8b87f8000000 }
            // n = 4, score = 200
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   c7870c01000000000000     | mov    dword ptr [edi + 0x10c], 0
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8b87f8000000         | mov                 eax, dword ptr [edi + 0xf8]

        $sequence_2 = { c20c00 837dfc46 7418 837dfc31 7412 }
            // n = 5, score = 200
            //   c20c00               | ret                 0xc
            //   837dfc46             | cmp                 dword ptr [ebp - 4], 0x46
            //   7418                 | je                  0x1a
            //   837dfc31             | cmp                 dword ptr [ebp - 4], 0x31
            //   7412                 | je                  0x14

        $sequence_3 = { 6a00 6a00 6810700000 68ffff0000 ff7704 e8???????? }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6810700000           | push                0x7010
            //   68ffff0000           | push                0xffff
            //   ff7704               | push                dword ptr [edi + 4]
            //   e8????????           |                     

        $sequence_4 = { 8b7d08 c7870c01000001000000 eb0d 8b7d08 c7870c01000000000000 8b7d08 }
            // n = 6, score = 200
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   c7870c01000001000000     | mov    dword ptr [edi + 0x10c], 1
            //   eb0d                 | jmp                 0xf
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   c7870c01000000000000     | mov    dword ptr [edi + 0x10c], 0
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]

        $sequence_5 = { 7525 83bed400000000 741c 8b15???????? 6a00 }
            // n = 5, score = 200
            //   7525                 | jne                 0x27
            //   83bed400000000       | cmp                 dword ptr [esi + 0xd4], 0
            //   741c                 | je                  0x1e
            //   8b15????????         |                     
            //   6a00                 | push                0

        $sequence_6 = { e8???????? eb25 83bfd000000005 751c ff750c }
            // n = 5, score = 200
            //   e8????????           |                     
            //   eb25                 | jmp                 0x27
            //   83bfd000000005       | cmp                 dword ptr [edi + 0xd0], 5
            //   751c                 | jne                 0x1e
            //   ff750c               | push                dword ptr [ebp + 0xc]

        $sequence_7 = { 7530 8b35???????? 837e2c2e 7409 }
            // n = 4, score = 200
            //   7530                 | jne                 0x32
            //   8b35????????         |                     
            //   837e2c2e             | cmp                 dword ptr [esi + 0x2c], 0x2e
            //   7409                 | je                  0xb

        $sequence_8 = { 83c4e0 8b35???????? 6a00 6a00 6a00 8d45e4 }
            // n = 6, score = 200
            //   83c4e0               | add                 esp, -0x20
            //   8b35????????         |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d45e4               | lea                 eax, [ebp - 0x1c]

        $sequence_9 = { e8???????? 83f8ff 750d b800000000 5f 5e }
            // n = 6, score = 200
            //   e8????????           |                     
            //   83f8ff               | cmp                 eax, -1
            //   750d                 | jne                 0xf
            //   b800000000           | mov                 eax, 0
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

    condition:
        7 of them and filesize < 352256
}