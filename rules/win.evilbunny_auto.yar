rule win_evilbunny_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.evilbunny."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.evilbunny"
        malpedia_rule_date = "20211007"
        malpedia_hash = "e5b790e0f888f252d49063a1251ca60ec2832535"
        malpedia_version = "20211008"
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
        $sequence_0 = { 8bbdd8feffff c1ef06 0bf9 33fe 33fa 03bdccfeffff 03bd50ffffff }
            // n = 7, score = 200
            //   8bbdd8feffff         | mov                 edi, dword ptr [ebp - 0x128]
            //   c1ef06               | shr                 edi, 6
            //   0bf9                 | or                  edi, ecx
            //   33fe                 | xor                 edi, esi
            //   33fa                 | xor                 edi, edx
            //   03bdccfeffff         | add                 edi, dword ptr [ebp - 0x134]
            //   03bd50ffffff         | add                 edi, dword ptr [ebp - 0xb0]

        $sequence_1 = { 8d4d84 e8???????? 50 68???????? 8b4db4 8b5108 8b45b4 }
            // n = 7, score = 200
            //   8d4d84               | lea                 ecx, dword ptr [ebp - 0x7c]
            //   e8????????           |                     
            //   50                   | push                eax
            //   68????????           |                     
            //   8b4db4               | mov                 ecx, dword ptr [ebp - 0x4c]
            //   8b5108               | mov                 edx, dword ptr [ecx + 8]
            //   8b45b4               | mov                 eax, dword ptr [ebp - 0x4c]

        $sequence_2 = { 8b4d94 890d???????? 833d????????00 7438 6a00 6a01 68???????? }
            // n = 7, score = 200
            //   8b4d94               | mov                 ecx, dword ptr [ebp - 0x6c]
            //   890d????????         |                     
            //   833d????????00       |                     
            //   7438                 | je                  0x3a
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   68????????           |                     

        $sequence_3 = { 8b55f8 8b8ab0060000 e8???????? 8b45f8 8b88ac060000 e8???????? 8bf4 }
            // n = 7, score = 200
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   8b8ab0060000         | mov                 ecx, dword ptr [edx + 0x6b0]
            //   e8????????           |                     
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8b88ac060000         | mov                 ecx, dword ptr [eax + 0x6ac]
            //   e8????????           |                     
            //   8bf4                 | mov                 esi, esp

        $sequence_4 = { e8???????? 8bf0 8b4dfc e8???????? 3bf0 774d 8b4dfc }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   e8????????           |                     
            //   3bf0                 | cmp                 esi, eax
            //   774d                 | ja                  0x4f
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_5 = { 8b4de0 894de8 c745d801000000 8b55e0 83c201 8955e0 e9???????? }
            // n = 7, score = 200
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   894de8               | mov                 dword ptr [ebp - 0x18], ecx
            //   c745d801000000       | mov                 dword ptr [ebp - 0x28], 1
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]
            //   83c201               | add                 edx, 1
            //   8955e0               | mov                 dword ptr [ebp - 0x20], edx
            //   e9????????           |                     

        $sequence_6 = { c745e400000000 c745bc00000000 c745a018421a00 8bf4 6a00 6a00 8b45e4 }
            // n = 7, score = 200
            //   c745e400000000       | mov                 dword ptr [ebp - 0x1c], 0
            //   c745bc00000000       | mov                 dword ptr [ebp - 0x44], 0
            //   c745a018421a00       | mov                 dword ptr [ebp - 0x60], 0x1a4218
            //   8bf4                 | mov                 esi, esp
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]

        $sequence_7 = { 8b5508 8b411c 2b4208 3d40010000 7f0e 6a14 8b4d08 }
            // n = 7, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b411c               | mov                 eax, dword ptr [ecx + 0x1c]
            //   2b4208               | sub                 eax, dword ptr [edx + 8]
            //   3d40010000           | cmp                 eax, 0x140
            //   7f0e                 | jg                  0x10
            //   6a14                 | push                0x14
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]

        $sequence_8 = { 8955f4 e9???????? 6a00 6a00 8b45f8 05ea0b0000 50 }
            // n = 7, score = 200
            //   8955f4               | mov                 dword ptr [ebp - 0xc], edx
            //   e9????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   05ea0b0000           | add                 eax, 0xbea
            //   50                   | push                eax

        $sequence_9 = { e8???????? 8bf4 50 ff15???????? 3bf4 e8???????? 8b4dfc }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8bf4                 | mov                 esi, esp
            //   50                   | push                eax
            //   ff15????????         |                     
            //   3bf4                 | cmp                 esi, esp
            //   e8????????           |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

    condition:
        7 of them and filesize < 1695744
}