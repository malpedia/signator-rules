rule win_crytox_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.crytox."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crytox"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
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
        $sequence_0 = { eb7d 85f6 7479 c645c800 e8???????? 85c0 89c3 }
            // n = 7, score = 100
            //   eb7d                 | mov                 eax, dword ptr [eax + 0xc]
            //   85f6                 | mov                 dword ptr [esp], eax
            //   7479                 | mov                 eax, dword ptr [ebp - 0xc]
            //   c645c800             | mov                 eax, dword ptr [eax + 8]
            //   e8????????           |                     
            //   85c0                 | jmp                 0x9ab
            //   89c3                 | cmp                 dword ptr [ebp - 0x14], 0x5f

        $sequence_1 = { dfe9 0f86c2e3ffff 89442410 89c1 c1fa02 db442410 c1f902 }
            // n = 7, score = 100
            //   dfe9                 | fistp               dword ptr [ebp - 0xf8]
            //   0f86c2e3ffff         | fldcw               word ptr [ebp - 0xf2]
            //   89442410             | mov                 eax, dword ptr [ebp - 0xf8]
            //   89c1                 | mov                 dword ptr [ebx + 0x212ac], eax
            //   c1fa02               | fild                qword ptr [ebp - 0x188]
            //   db442410             | fstp                qword ptr [esp]
            //   c1f902               | lea                 eax, [ebp - 0x80]

        $sequence_2 = { e8???????? 8b4510 3b4518 741d 0fbf45c4 c1e002 89442408 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b4510               | cmp                 byte ptr [esp + 0x28], 0
            //   3b4518               | mov                 dword ptr [ebx + 0x138], eax
            //   741d                 | mov                 eax, dword ptr [esp + 0x54]
            //   0fbf45c4             | mov                 dword ptr [ebx + 0x13c], eax
            //   c1e002               | mov                 eax, dword ptr [esp + 0x58]
            //   89442408             | mov                 eax, dword ptr [esp + 0x50]

        $sequence_3 = { e8???????? 89c3 8b45dc 85c0 0f84adfeffff 8d65f4 89d8 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   89c3                 | mov                 eax, dword ptr [ebp + 0x10]
            //   8b45dc               | mov                 dword ptr [esp + 8], esi
            //   85c0                 | mov                 dword ptr [esp + 4], edi
            //   0f84adfeffff         | mov                 dword ptr [esp], esi
            //   8d65f4               | mov                 edi, dword ptr [ebp - 0xa4]
            //   89d8                 | mov                 dword ptr [esp + 0xc], edi

        $sequence_4 = { eb02 d9c9 83c301 038d30ffffff 399d04ffffff 7f8e ddd9 }
            // n = 7, score = 100
            //   eb02                 | mov                 ebx, dword ptr [eax + 0xa8]
            //   d9c9                 | mov                 edi, eax
            //   83c301               | fxch                st(1)
            //   038d30ffffff         | cmp                 byte ptr [ebx + 0xc], 0
            //   399d04ffffff         | fucomip             st(1)
            //   7f8e                 | ja                  0x4f0
            //   ddd9                 | fld                 st(0)

        $sequence_5 = { f1 807de700 89d3 7510 6bc22c 80b84442660000 0f85ac000000 }
            // n = 7, score = 100
            //   f1                   | jmp                 0x77
            //   807de700             | add                 esi, edi
            //   89d3                 | inc                 edx
            //   7510                 | jmp                 0x71
            //   6bc22c               | fstp                st(0)
            //   80b84442660000       | fstp                st(0)
            //   0f85ac000000         | add                 esp, 0x24

        $sequence_6 = { c5c5fe3d???????? c5c572e70e c5fd7f9c24000b0000 c5e572e50e c5d572e60e c5fd7f9c24e0090000 c5ddfe15???????? }
            // n = 7, score = 100
            //   c5c5fe3d????????     |                     
            //   c5c572e70e           | vpsrad              ymm7, ymm7, 2
            //   c5fd7f9c24000b0000     | vpsrad    ymm6, ymm6, 2
            //   c5e572e50e           | vpackssdw           ymm7, ymm7, ymm6
            //   c5d572e60e           | vpsrad              ymm3, ymm3, 2
            //   c5fd7f9c24e0090000     | vpsrad    ymm2, ymm2, 2
            //   c5ddfe15????????     |                     

        $sequence_7 = { dee9 d95dc0 8b45e0 83c001 8d148500000000 8b4508 01d0 }
            // n = 7, score = 100
            //   dee9                 | mov                 edx, dword ptr [ebp - 0x20]
            //   d95dc0               | add                 edx, ecx
            //   8b45e0               | fld                 dword ptr [edx]
            //   83c001               | fsubrp              st(1)
            //   8d148500000000       | mov                 ecx, dword ptr [ebp - 0xe8]
            //   8b4508               | add                 ebx, 1
            //   01d0                 | fstp                dword ptr [ecx + eax*4]

        $sequence_8 = { e9???????? 8b7d24 8b4510 85ff c70000000000 742b 8b4508 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8b7d24               | mov                 dword ptr [ebp - 0x48], eax
            //   8b4510               | mov                 eax, dword ptr [ebp + 8]
            //   85ff                 | mov                 eax, dword ptr [eax + 0x44]
            //   c70000000000         | mov                 edx, dword ptr [ebp - 0x30]
            //   742b                 | shl                 edx, 2
            //   8b4508               | mov                 eax, dword ptr [ebp - 0x3c]

        $sequence_9 = { dec9 d96c2424 db5c2420 d96c2426 8b742420 d9e8 dfe9 }
            // n = 7, score = 100
            //   dec9                 | cmp                 ecx, esi
            //   d96c2424             | faddp               st(5)
            //   db5c2420             | fmul                st(1), st(0)
            //   d96c2426             | fxch                st(1)
            //   8b742420             | faddp               st(2)
            //   d9e8                 | fmul                st(0)
            //   dfe9                 | faddp               st(2)

    condition:
        7 of them and filesize < 6156288
}