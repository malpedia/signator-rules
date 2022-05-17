rule win_flusihoc_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.flusihoc."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.flusihoc"
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
        $sequence_0 = { ffd3 8b442410 6aff 50 }
            // n = 4, score = 400
            //   ffd3                 | call                ebx
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   6aff                 | push                -1
            //   50                   | push                eax

        $sequence_1 = { 51 ffd6 8b542414 52 ffd6 6a0a }
            // n = 6, score = 400
            //   51                   | push                ecx
            //   ffd6                 | call                esi
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   52                   | push                edx
            //   ffd6                 | call                esi
            //   6a0a                 | push                0xa

        $sequence_2 = { 8d442428 6a00 50 c744242c44000000 }
            // n = 4, score = 400
            //   8d442428             | lea                 eax, [esp + 0x28]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   c744242c44000000     | mov                 dword ptr [esp + 0x2c], 0x44

        $sequence_3 = { 56 57 6a40 8d442428 6a00 }
            // n = 5, score = 400
            //   56                   | push                esi
            //   57                   | push                edi
            //   6a40                 | push                0x40
            //   8d442428             | lea                 eax, [esp + 0x28]
            //   6a00                 | push                0

        $sequence_4 = { 8d85b0feffff 50 6802000080 ff15???????? 85c0 }
            // n = 5, score = 400
            //   8d85b0feffff         | lea                 eax, [ebp - 0x150]
            //   50                   | push                eax
            //   6802000080           | push                0x80000002
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_5 = { 8bec 83e4f8 81ec74040000 a1???????? 33c4 89842470040000 53 }
            // n = 7, score = 400
            //   8bec                 | mov                 ebp, esp
            //   83e4f8               | and                 esp, 0xfffffff8
            //   81ec74040000         | sub                 esp, 0x474
            //   a1????????           |                     
            //   33c4                 | xor                 eax, esp
            //   89842470040000       | mov                 dword ptr [esp + 0x470], eax
            //   53                   | push                ebx

        $sequence_6 = { 6a00 6a01 6a02 ff15???????? 6a10 8d4c2414 }
            // n = 6, score = 400
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   6a02                 | push                2
            //   ff15????????         |                     
            //   6a10                 | push                0x10
            //   8d4c2414             | lea                 ecx, [esp + 0x14]

        $sequence_7 = { fe06 fe4e17 83f834 7503 fe4e18 }
            // n = 5, score = 400
            //   fe06                 | inc                 byte ptr [esi]
            //   fe4e17               | dec                 byte ptr [esi + 0x17]
            //   83f834               | cmp                 eax, 0x34
            //   7503                 | jne                 5
            //   fe4e18               | dec                 byte ptr [esi + 0x18]

        $sequence_8 = { 33c4 898424e00b0000 53 56 8b7508 }
            // n = 5, score = 400
            //   33c4                 | xor                 eax, esp
            //   898424e00b0000       | mov                 dword ptr [esp + 0xbe0], eax
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]

        $sequence_9 = { 8d7c2428 50 f3a5 c684246401000000 e8???????? }
            // n = 5, score = 400
            //   8d7c2428             | lea                 edi, [esp + 0x28]
            //   50                   | push                eax
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   c684246401000000     | mov                 byte ptr [esp + 0x164], 0
            //   e8????????           |                     

        $sequence_10 = { f3a5 c684246402000000 e8???????? 68d6000000 }
            // n = 4, score = 400
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   c684246402000000     | mov                 byte ptr [esp + 0x264], 0
            //   e8????????           |                     
            //   68d6000000           | push                0xd6

        $sequence_11 = { 6aff 50 ff15???????? 8b4c2410 51 }
            // n = 5, score = 400
            //   6aff                 | push                -1
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   51                   | push                ecx

        $sequence_12 = { 8d4de8 3c7c 740f 3c0a 740b }
            // n = 5, score = 400
            //   8d4de8               | lea                 ecx, [ebp - 0x18]
            //   3c7c                 | cmp                 al, 0x7c
            //   740f                 | je                  0x11
            //   3c0a                 | cmp                 al, 0xa
            //   740b                 | je                  0xd

        $sequence_13 = { 8d95f4feffff 52 6806000200 6a00 68???????? 6802000080 ff15???????? }
            // n = 7, score = 200
            //   8d95f4feffff         | lea                 edx, [ebp - 0x10c]
            //   52                   | push                edx
            //   6806000200           | push                0x20006
            //   6a00                 | push                0
            //   68????????           |                     
            //   6802000080           | push                0x80000002
            //   ff15????????         |                     

        $sequence_14 = { 8b95f4feffff 52 ff15???????? 8b4dfc 33cd 33c0 e8???????? }
            // n = 7, score = 200
            //   8b95f4feffff         | mov                 edx, dword ptr [ebp - 0x10c]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   33cd                 | xor                 ecx, ebp
            //   33c0                 | xor                 eax, eax
            //   e8????????           |                     

        $sequence_15 = { ff15???????? 85c0 752f 8b8df4feffff 6804010000 }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   752f                 | jne                 0x31
            //   8b8df4feffff         | mov                 ecx, dword ptr [ebp - 0x10c]
            //   6804010000           | push                0x104

    condition:
        7 of them and filesize < 319488
}