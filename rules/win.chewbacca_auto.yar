rule win_chewbacca_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.chewbacca."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chewbacca"
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
        $sequence_0 = { c744240c5f0f0000 89442408 c7442404???????? a1???????? 83c040 890424 e8???????? }
            // n = 7, score = 100
            //   c744240c5f0f0000     | mov                 dword ptr [esp + 0xc], 0xf5f
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   c7442404????????     |                     
            //   a1????????           |                     
            //   83c040               | add                 eax, 0x40
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     

        $sequence_1 = { e8???????? e8???????? 50 85c0 7534 8b45f4 ba00000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   e8????????           |                     
            //   50                   | push                eax
            //   85c0                 | test                eax, eax
            //   7534                 | jne                 0x36
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   ba00000000           | mov                 edx, 0

        $sequence_2 = { e8???????? 8b4634 85c0 7408 890424 e8???????? 8b4638 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b4634               | mov                 eax, dword ptr [esi + 0x34]
            //   85c0                 | test                eax, eax
            //   7408                 | je                  0xa
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   8b4638               | mov                 eax, dword ptr [esi + 0x38]

        $sequence_3 = { c7442414b9386800 c74424104b3e6800 c744240c1b020000 89442408 c7442404???????? a1???????? 83c040 }
            // n = 7, score = 100
            //   c7442414b9386800     | mov                 dword ptr [esp + 0x14], 0x6838b9
            //   c74424104b3e6800     | mov                 dword ptr [esp + 0x10], 0x683e4b
            //   c744240c1b020000     | mov                 dword ptr [esp + 0xc], 0x21b
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   c7442404????????     |                     
            //   a1????????           |                     
            //   83c040               | add                 eax, 0x40

        $sequence_4 = { c744240c48306500 c7442408???????? c744240400080000 c7042406000000 e8???????? c6430408 8b44242c }
            // n = 7, score = 100
            //   c744240c48306500     | mov                 dword ptr [esp + 0xc], 0x653048
            //   c7442408????????     |                     
            //   c744240400080000     | mov                 dword ptr [esp + 4], 0x800
            //   c7042406000000       | mov                 dword ptr [esp], 6
            //   e8????????           |                     
            //   c6430408             | mov                 byte ptr [ebx + 4], 8
            //   8b44242c             | mov                 eax, dword ptr [esp + 0x2c]

        $sequence_5 = { c744240cccae6500 c7442408???????? c744240404000000 c7042406000000 e8???????? 89f0 81c45c040000 }
            // n = 7, score = 100
            //   c744240cccae6500     | mov                 dword ptr [esp + 0xc], 0x65aecc
            //   c7442408????????     |                     
            //   c744240404000000     | mov                 dword ptr [esp + 4], 4
            //   c7042406000000       | mov                 dword ptr [esp], 6
            //   e8????????           |                     
            //   89f0                 | mov                 eax, esi
            //   81c45c040000         | add                 esp, 0x45c

        $sequence_6 = { c7442408???????? c744240401000000 c7042403000000 e8???????? b8ffffffff eb64 c744240801000000 }
            // n = 7, score = 100
            //   c7442408????????     |                     
            //   c744240401000000     | mov                 dword ptr [esp + 4], 1
            //   c7042403000000       | mov                 dword ptr [esp], 3
            //   e8????????           |                     
            //   b8ffffffff           | mov                 eax, 0xffffffff
            //   eb64                 | jmp                 0x66
            //   c744240801000000     | mov                 dword ptr [esp + 8], 1

        $sequence_7 = { e8???????? 8945f8 8b55fc 8b45f8 e8???????? 8b45f8 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   e8????????           |                     
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   e8????????           |                     

        $sequence_8 = { e8???????? 8b45c4 8d55f4 e8???????? 8d4dc4 ba???????? 8b45f4 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b45c4               | mov                 eax, dword ptr [ebp - 0x3c]
            //   8d55f4               | lea                 edx, dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   8d4dc4               | lea                 ecx, dword ptr [ebp - 0x3c]
            //   ba????????           |                     
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_9 = { c7442408???????? c744240400100000 c7042404000000 e8???????? 891c24 e8???????? 8b442428 }
            // n = 7, score = 100
            //   c7442408????????     |                     
            //   c744240400100000     | mov                 dword ptr [esp + 4], 0x1000
            //   c7042404000000       | mov                 dword ptr [esp], 4
            //   e8????????           |                     
            //   891c24               | mov                 dword ptr [esp], ebx
            //   e8????????           |                     
            //   8b442428             | mov                 eax, dword ptr [esp + 0x28]

    condition:
        7 of them and filesize < 9764864
}