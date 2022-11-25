rule win_mrdec_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.mrdec."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mrdec"
        malpedia_rule_date = "20221118"
        malpedia_hash = "e0702e2e6d1d00da65c8a29a4ebacd0a4c59e1af"
        malpedia_version = "20221125"
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
        $sequence_0 = { c20400 55 8bec 81c488fdffff 8d85a8fdffff 50 ff7508 }
            // n = 7, score = 100
            //   c20400               | ret                 4
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81c488fdffff         | add                 esp, 0xfffffd88
            //   8d85a8fdffff         | lea                 eax, [ebp - 0x258]
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_1 = { 8d45f4 50 ff35???????? 68???????? ff75fc e8???????? ff75fc }
            // n = 7, score = 100
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   ff35????????         |                     
            //   68????????           |                     
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   ff75fc               | push                dword ptr [ebp - 4]

        $sequence_2 = { e8???????? ff05???????? 6a00 6a00 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   ff05????????         |                     
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_3 = { ff75f4 e8???????? 83f800 7605 8945f0 eb02 eb91 }
            // n = 7, score = 100
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   83f800               | cmp                 eax, 0
            //   7605                 | jbe                 7
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   eb02                 | jmp                 4
            //   eb91                 | jmp                 0xffffff93

        $sequence_4 = { b919000000 fc f3a4 5f c6072e }
            // n = 5, score = 100
            //   b919000000           | mov                 ecx, 0x19
            //   fc                   | cld                 
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   5f                   | pop                 edi
            //   c6072e               | mov                 byte ptr [edi], 0x2e

        $sequence_5 = { 8d45f8 50 8d85e4feffff 50 6a00 6a01 6a00 }
            // n = 7, score = 100
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   8d85e4feffff         | lea                 eax, [ebp - 0x11c]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   6a00                 | push                0

        $sequence_6 = { e8???????? 68???????? 6a00 6a00 6814010000 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   68????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6814010000           | push                0x114

        $sequence_7 = { 81c488fdffff 8d85a8fdffff 50 ff7508 e8???????? }
            // n = 5, score = 100
            //   81c488fdffff         | add                 esp, 0xfffffd88
            //   8d85a8fdffff         | lea                 eax, [ebp - 0x258]
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     

        $sequence_8 = { ff75f4 e8???????? ff75f4 e8???????? 6a00 ff75f8 e8???????? }
            // n = 7, score = 100
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   6a00                 | push                0
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   e8????????           |                     

        $sequence_9 = { 8d8620800000 50 e8???????? c784461a80000000000000 }
            // n = 4, score = 100
            //   8d8620800000         | lea                 eax, [esi + 0x8020]
            //   50                   | push                eax
            //   e8????????           |                     
            //   c784461a80000000000000     | mov    dword ptr [esi + eax*2 + 0x801a], 0

    condition:
        7 of them and filesize < 44864
}