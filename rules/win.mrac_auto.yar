rule win_mrac_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.mrac."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mrac"
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
        $sequence_0 = { e8???????? 3476 8d8c24100e0000 6a17 8884242e0e0000 e8???????? 3469 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   3476                 | xor                 al, 0x76
            //   8d8c24100e0000       | lea                 ecx, dword ptr [esp + 0xe10]
            //   6a17                 | push                0x17
            //   8884242e0e0000       | mov                 byte ptr [esp + 0xe2e], al
            //   e8????????           |                     
            //   3469                 | xor                 al, 0x69

        $sequence_1 = { c684241407000032 c68424150700003d c68424160700007b c68424170700007f c684241807000032 c684241907000061 c684241a07000063 }
            // n = 7, score = 200
            //   c684241407000032     | mov                 byte ptr [esp + 0x714], 0x32
            //   c68424150700003d     | mov                 byte ptr [esp + 0x715], 0x3d
            //   c68424160700007b     | mov                 byte ptr [esp + 0x716], 0x7b
            //   c68424170700007f     | mov                 byte ptr [esp + 0x717], 0x7f
            //   c684241807000032     | mov                 byte ptr [esp + 0x718], 0x32
            //   c684241907000061     | mov                 byte ptr [esp + 0x719], 0x61
            //   c684241a07000063     | mov                 byte ptr [esp + 0x71a], 0x63

        $sequence_2 = { 884589 8b8578ffffff 040e 3472 88458a 8b8578ffffff 040f }
            // n = 7, score = 200
            //   884589               | mov                 byte ptr [ebp - 0x77], al
            //   8b8578ffffff         | mov                 eax, dword ptr [ebp - 0x88]
            //   040e                 | add                 al, 0xe
            //   3472                 | xor                 al, 0x72
            //   88458a               | mov                 byte ptr [ebp - 0x76], al
            //   8b8578ffffff         | mov                 eax, dword ptr [ebp - 0x88]
            //   040f                 | add                 al, 0xf

        $sequence_3 = { 8885a2fbffff 8b8580fbffff 041f 3475 8885a3fbffff 8b8580fbffff 0420 }
            // n = 7, score = 200
            //   8885a2fbffff         | mov                 byte ptr [ebp - 0x45e], al
            //   8b8580fbffff         | mov                 eax, dword ptr [ebp - 0x480]
            //   041f                 | add                 al, 0x1f
            //   3475                 | xor                 al, 0x75
            //   8885a3fbffff         | mov                 byte ptr [ebp - 0x45d], al
            //   8b8580fbffff         | mov                 eax, dword ptr [ebp - 0x480]
            //   0420                 | add                 al, 0x20

        $sequence_4 = { 6a04 8884243f0a0000 e8???????? 3473 8d8c24340a0000 6a05 888424400a0000 }
            // n = 7, score = 200
            //   6a04                 | push                4
            //   8884243f0a0000       | mov                 byte ptr [esp + 0xa3f], al
            //   e8????????           |                     
            //   3473                 | xor                 al, 0x73
            //   8d8c24340a0000       | lea                 ecx, dword ptr [esp + 0xa34]
            //   6a05                 | push                5
            //   888424400a0000       | mov                 byte ptr [esp + 0xa40], al

        $sequence_5 = { 6a56 8884247b090000 e8???????? 0473 8d8c2474090000 6a56 8884247c090000 }
            // n = 7, score = 200
            //   6a56                 | push                0x56
            //   8884247b090000       | mov                 byte ptr [esp + 0x97b], al
            //   e8????????           |                     
            //   0473                 | add                 al, 0x73
            //   8d8c2474090000       | lea                 ecx, dword ptr [esp + 0x974]
            //   6a56                 | push                0x56
            //   8884247c090000       | mov                 byte ptr [esp + 0x97c], al

        $sequence_6 = { 8d8c24140a0000 6a12 8884242d0a0000 e8???????? 3424 8884242a0a0000 6a13 }
            // n = 7, score = 200
            //   8d8c24140a0000       | lea                 ecx, dword ptr [esp + 0xa14]
            //   6a12                 | push                0x12
            //   8884242d0a0000       | mov                 byte ptr [esp + 0xa2d], al
            //   e8????????           |                     
            //   3424                 | xor                 al, 0x24
            //   8884242a0a0000       | mov                 byte ptr [esp + 0xa2a], al
            //   6a13                 | push                0x13

        $sequence_7 = { 83e801 746a 83e805 7456 83e801 0f859b010000 c745e0b4844400 }
            // n = 7, score = 200
            //   83e801               | sub                 eax, 1
            //   746a                 | je                  0x6c
            //   83e805               | sub                 eax, 5
            //   7456                 | je                  0x58
            //   83e801               | sub                 eax, 1
            //   0f859b010000         | jne                 0x1a1
            //   c745e0b4844400       | mov                 dword ptr [ebp - 0x20], 0x4484b4

        $sequence_8 = { c684243701000000 3431 88842436010000 8a842410010000 e8???????? 8bc8 }
            // n = 6, score = 200
            //   c684243701000000     | mov                 byte ptr [esp + 0x137], 0
            //   3431                 | xor                 al, 0x31
            //   88842436010000       | mov                 byte ptr [esp + 0x136], al
            //   8a842410010000       | mov                 al, byte ptr [esp + 0x110]
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax

        $sequence_9 = { 3455 888522fbffff 8b8500fbffff 041f c68524fbffff00 3450 33d2 }
            // n = 7, score = 200
            //   3455                 | xor                 al, 0x55
            //   888522fbffff         | mov                 byte ptr [ebp - 0x4de], al
            //   8b8500fbffff         | mov                 eax, dword ptr [ebp - 0x500]
            //   041f                 | add                 al, 0x1f
            //   c68524fbffff00       | mov                 byte ptr [ebp - 0x4dc], 0
            //   3450                 | xor                 al, 0x50
            //   33d2                 | xor                 edx, edx

    condition:
        7 of them and filesize < 745472
}