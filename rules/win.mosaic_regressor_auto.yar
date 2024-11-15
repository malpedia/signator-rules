rule win_mosaic_regressor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.mosaic_regressor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mosaic_regressor"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
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
        $sequence_0 = { e8???????? 670010 386700 1023 d18a0688078a }
            // n = 5, score = 100
            //   e8????????           |                     
            //   670010               | add                 byte ptr [bx + si], dl
            //   386700               | cmp                 byte ptr [edi], ah
            //   1023                 | adc                 byte ptr [ebx], ah
            //   d18a0688078a         | ror                 dword ptr [edx - 0x75f877fa], 1

        $sequence_1 = { 8975e0 8db1d0a70010 8975e4 eb2a }
            // n = 4, score = 100
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi
            //   8db1d0a70010         | lea                 esi, [ecx + 0x1000a7d0]
            //   8975e4               | mov                 dword ptr [ebp - 0x1c], esi
            //   eb2a                 | jmp                 0x2c

        $sequence_2 = { 85c0 7456 8b4de0 8d0c8de0b70010 8901 8305????????20 }
            // n = 6, score = 100
            //   85c0                 | test                eax, eax
            //   7456                 | je                  0x58
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   8d0c8de0b70010       | lea                 ecx, [ecx*4 + 0x1000b7e0]
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8305????????20       |                     

        $sequence_3 = { f3a4 6a1c 8d8c2480060000 51 6a00 ffd5 8d842478060000 }
            // n = 7, score = 100
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   6a1c                 | push                0x1c
            //   8d8c2480060000       | lea                 ecx, [esp + 0x680]
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   ffd5                 | call                ebp
            //   8d842478060000       | lea                 eax, [esp + 0x678]

        $sequence_4 = { 8d442460 50 6a00 ffd5 8d442458 48 8d4900 }
            // n = 7, score = 100
            //   8d442460             | lea                 eax, [esp + 0x60]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ffd5                 | call                ebp
            //   8d442458             | lea                 eax, [esp + 0x58]
            //   48                   | dec                 eax
            //   8d4900               | lea                 ecx, [ecx]

        $sequence_5 = { 895008 8d542458 52 88480c }
            // n = 4, score = 100
            //   895008               | mov                 dword ptr [eax + 8], edx
            //   8d542458             | lea                 edx, [esp + 0x58]
            //   52                   | push                edx
            //   88480c               | mov                 byte ptr [eax + 0xc], cl

        $sequence_6 = { c744241444000000 8bc8 90 8a10 }
            // n = 4, score = 100
            //   c744241444000000     | mov                 dword ptr [esp + 0x14], 0x44
            //   8bc8                 | mov                 ecx, eax
            //   90                   | nop                 
            //   8a10                 | mov                 dl, byte ptr [eax]

        $sequence_7 = { 6a06 89430c 8d4310 8d89c4a70010 5a }
            // n = 5, score = 100
            //   6a06                 | push                6
            //   89430c               | mov                 dword ptr [ebx + 0xc], eax
            //   8d4310               | lea                 eax, [ebx + 0x10]
            //   8d89c4a70010         | lea                 ecx, [ecx + 0x1000a7c4]
            //   5a                   | pop                 edx

        $sequence_8 = { 8bff 55 8bec 8b4508 ff34c578a10010 ff15???????? 5d }
            // n = 7, score = 100
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   ff34c578a10010       | push                dword ptr [eax*8 + 0x1000a178]
            //   ff15????????         |                     
            //   5d                   | pop                 ebp

        $sequence_9 = { 6a00 6a00 6a00 8d942498080000 }
            // n = 4, score = 100
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d942498080000       | lea                 edx, [esp + 0x898]

    condition:
        7 of them and filesize < 113664
}