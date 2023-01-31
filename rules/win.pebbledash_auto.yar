rule win_pebbledash_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.pebbledash."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pebbledash"
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
        $sequence_0 = { 83c40c 8b4d08 c7011c010000 8b5508 52 ff15???????? }
            // n = 6, score = 100
            //   83c40c               | add                 esp, 0xc
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   c7011c010000         | mov                 dword ptr [ecx], 0x11c
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_1 = { 66ab 837d1000 743b 8b4510 50 e8???????? }
            // n = 6, score = 100
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   837d1000             | cmp                 dword ptr [ebp + 0x10], 0
            //   743b                 | je                  0x3d
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_2 = { 6a03 68000000c0 8d8dc0f7ffff 51 ff15???????? }
            // n = 5, score = 100
            //   6a03                 | push                3
            //   68000000c0           | push                0xc0000000
            //   8d8dc0f7ffff         | lea                 ecx, [ebp - 0x840]
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_3 = { e9???????? 837dfc00 752f 8d55f0 52 8b4508 }
            // n = 6, score = 100
            //   e9????????           |                     
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0
            //   752f                 | jne                 0x31
            //   8d55f0               | lea                 edx, [ebp - 0x10]
            //   52                   | push                edx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_4 = { c645f000 c645f118 c645f200 c645f319 c645dc00 c645dd0b c645de00 }
            // n = 7, score = 100
            //   c645f000             | mov                 byte ptr [ebp - 0x10], 0
            //   c645f118             | mov                 byte ptr [ebp - 0xf], 0x18
            //   c645f200             | mov                 byte ptr [ebp - 0xe], 0
            //   c645f319             | mov                 byte ptr [ebp - 0xd], 0x19
            //   c645dc00             | mov                 byte ptr [ebp - 0x24], 0
            //   c645dd0b             | mov                 byte ptr [ebp - 0x23], 0xb
            //   c645de00             | mov                 byte ptr [ebp - 0x22], 0

        $sequence_5 = { 8b95ccfeffff 8b4204 8945fc 8d8dd0feffff 51 8b550c 52 }
            // n = 7, score = 100
            //   8b95ccfeffff         | mov                 edx, dword ptr [ebp - 0x134]
            //   8b4204               | mov                 eax, dword ptr [edx + 4]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8d8dd0feffff         | lea                 ecx, [ebp - 0x130]
            //   51                   | push                ecx
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   52                   | push                edx

        $sequence_6 = { 68???????? ff15???????? 50 ff15???????? 8945d0 837dd000 7419 }
            // n = 7, score = 100
            //   68????????           |                     
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax
            //   837dd000             | cmp                 dword ptr [ebp - 0x30], 0
            //   7419                 | je                  0x1b

        $sequence_7 = { 8b8594baffff 8b08 8b5508 3b5110 7d11 8b8594baffff 8b08 }
            // n = 7, score = 100
            //   8b8594baffff         | mov                 eax, dword ptr [ebp - 0x456c]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   3b5110               | cmp                 edx, dword ptr [ecx + 0x10]
            //   7d11                 | jge                 0x13
            //   8b8594baffff         | mov                 eax, dword ptr [ebp - 0x456c]
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_8 = { 8b8db0deffff e8???????? 85c0 7419 6a16 8b45f8 50 }
            // n = 7, score = 100
            //   8b8db0deffff         | mov                 ecx, dword ptr [ebp - 0x2150]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7419                 | je                  0x1b
            //   6a16                 | push                0x16
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   50                   | push                eax

        $sequence_9 = { 85c9 7410 8b55f4 d1ea 81f22083b8ed 8955f4 eb08 }
            // n = 7, score = 100
            //   85c9                 | test                ecx, ecx
            //   7410                 | je                  0x12
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   d1ea                 | shr                 edx, 1
            //   81f22083b8ed         | xor                 edx, 0xedb88320
            //   8955f4               | mov                 dword ptr [ebp - 0xc], edx
            //   eb08                 | jmp                 0xa

    condition:
        7 of them and filesize < 360448
}