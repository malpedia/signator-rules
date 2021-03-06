rule win_spaceship_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.spaceship."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.spaceship"
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
        $sequence_0 = { 50 8d4c2414 55 51 52 ff15???????? }
            // n = 6, score = 100
            //   50                   | push                eax
            //   8d4c2414             | lea                 ecx, [esp + 0x14]
            //   55                   | push                ebp
            //   51                   | push                ecx
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_1 = { ff54242c 85c0 7427 8b442420 8d942454020000 6800020000 }
            // n = 6, score = 100
            //   ff54242c             | call                dword ptr [esp + 0x2c]
            //   85c0                 | test                eax, eax
            //   7427                 | je                  0x29
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   8d942454020000       | lea                 edx, [esp + 0x254]
            //   6800020000           | push                0x200

        $sequence_2 = { 52 50 8d8c2458040000 68???????? 51 e8???????? 8d942460040000 }
            // n = 7, score = 100
            //   52                   | push                edx
            //   50                   | push                eax
            //   8d8c2458040000       | lea                 ecx, [esp + 0x458]
            //   68????????           |                     
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8d942460040000       | lea                 edx, [esp + 0x460]

        $sequence_3 = { 66899c24ee040000 c78424f004000014674100 66c78424f40400001e00 66899c24f6040000 c78424f80400000c674100 66c78424fc0400001f00 66899c24fe040000 }
            // n = 7, score = 100
            //   66899c24ee040000     | mov                 word ptr [esp + 0x4ee], bx
            //   c78424f004000014674100     | mov    dword ptr [esp + 0x4f0], 0x416714
            //   66c78424f40400001e00     | mov    word ptr [esp + 0x4f4], 0x1e
            //   66899c24f6040000     | mov                 word ptr [esp + 0x4f6], bx
            //   c78424f80400000c674100     | mov    dword ptr [esp + 0x4f8], 0x41670c
            //   66c78424fc0400001f00     | mov    word ptr [esp + 0x4fc], 0x1f
            //   66899c24fe040000     | mov                 word ptr [esp + 0x4fe], bx

        $sequence_4 = { 0f859a000000 8d442410 6804010000 50 ff15???????? }
            // n = 5, score = 100
            //   0f859a000000         | jne                 0xa0
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   6804010000           | push                0x104
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_5 = { 52 e8???????? a1???????? 83c408 40 a3???????? ebba }
            // n = 7, score = 100
            //   52                   | push                edx
            //   e8????????           |                     
            //   a1????????           |                     
            //   83c408               | add                 esp, 8
            //   40                   | inc                 eax
            //   a3????????           |                     
            //   ebba                 | jmp                 0xffffffbc

        $sequence_6 = { 33c9 8a8828494100 894de8 eb17 8b55f4 81e2ffff0000 c1fa07 }
            // n = 7, score = 100
            //   33c9                 | xor                 ecx, ecx
            //   8a8828494100         | mov                 cl, byte ptr [eax + 0x414928]
            //   894de8               | mov                 dword ptr [ebp - 0x18], ecx
            //   eb17                 | jmp                 0x19
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   81e2ffff0000         | and                 edx, 0xffff
            //   c1fa07               | sar                 edx, 7

        $sequence_7 = { 8b1485207f4100 85d2 7408 8901 b801000000 }
            // n = 5, score = 100
            //   8b1485207f4100       | mov                 edx, dword ptr [eax*4 + 0x417f20]
            //   85d2                 | test                edx, edx
            //   7408                 | je                  0xa
            //   8901                 | mov                 dword ptr [ecx], eax
            //   b801000000           | mov                 eax, 1

        $sequence_8 = { 85c0 0f859a000000 8d442410 6804010000 }
            // n = 4, score = 100
            //   85c0                 | test                eax, eax
            //   0f859a000000         | jne                 0xa0
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   6804010000           | push                0x104

        $sequence_9 = { 8b4c241c 8b54241a 25ffff0000 81e1ffff0000 50 8b44241a }
            // n = 6, score = 100
            //   8b4c241c             | mov                 ecx, dword ptr [esp + 0x1c]
            //   8b54241a             | mov                 edx, dword ptr [esp + 0x1a]
            //   25ffff0000           | and                 eax, 0xffff
            //   81e1ffff0000         | and                 ecx, 0xffff
            //   50                   | push                eax
            //   8b44241a             | mov                 eax, dword ptr [esp + 0x1a]

    condition:
        7 of them and filesize < 262144
}