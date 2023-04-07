rule win_playwork_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.playwork."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.playwork"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
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
        $sequence_0 = { 68???????? eb30 8d8548feffff 50 68???????? ffd7 }
            // n = 6, score = 100
            //   68????????           |                     
            //   eb30                 | jmp                 0x32
            //   8d8548feffff         | lea                 eax, [ebp - 0x1b8]
            //   50                   | push                eax
            //   68????????           |                     
            //   ffd7                 | call                edi

        $sequence_1 = { 7504 33ff eb31 8d85e4f4ffff 50 ffd6 }
            // n = 6, score = 100
            //   7504                 | jne                 6
            //   33ff                 | xor                 edi, edi
            //   eb31                 | jmp                 0x33
            //   8d85e4f4ffff         | lea                 eax, [ebp - 0xb1c]
            //   50                   | push                eax
            //   ffd6                 | call                esi

        $sequence_2 = { 8bda c1eb18 33349d34573f00 0fb6d9 c1e918 33349d344b3f00 8bdf }
            // n = 7, score = 100
            //   8bda                 | mov                 ebx, edx
            //   c1eb18               | shr                 ebx, 0x18
            //   33349d34573f00       | xor                 esi, dword ptr [ebx*4 + 0x3f5734]
            //   0fb6d9               | movzx               ebx, cl
            //   c1e918               | shr                 ecx, 0x18
            //   33349d344b3f00       | xor                 esi, dword ptr [ebx*4 + 0x3f4b34]
            //   8bdf                 | mov                 ebx, edi

        $sequence_3 = { ffd6 8b3d???????? 85c0 7513 6888130000 }
            // n = 5, score = 100
            //   ffd6                 | call                esi
            //   8b3d????????         |                     
            //   85c0                 | test                eax, eax
            //   7513                 | jne                 0x15
            //   6888130000           | push                0x1388

        $sequence_4 = { 83c418 8d858cfdffff 50 8d857cf9ffff 50 ff15???????? }
            // n = 6, score = 100
            //   83c418               | add                 esp, 0x18
            //   8d858cfdffff         | lea                 eax, [ebp - 0x274]
            //   50                   | push                eax
            //   8d857cf9ffff         | lea                 eax, [ebp - 0x684]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_5 = { 50 e8???????? 83c40c 8d85e8f7ffff 50 ff7508 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d85e8f7ffff         | lea                 eax, [ebp - 0x818]
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_6 = { 8d55b8 53 52 8b08 6a01 50 }
            // n = 6, score = 100
            //   8d55b8               | lea                 edx, [ebp - 0x48]
            //   53                   | push                ebx
            //   52                   | push                edx
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   6a01                 | push                1
            //   50                   | push                eax

        $sequence_7 = { 837d0800 74e0 037508 2b5d08 75e2 6a01 5e }
            // n = 7, score = 100
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   74e0                 | je                  0xffffffe2
            //   037508               | add                 esi, dword ptr [ebp + 8]
            //   2b5d08               | sub                 ebx, dword ptr [ebp + 8]
            //   75e2                 | jne                 0xffffffe4
            //   6a01                 | push                1
            //   5e                   | pop                 esi

        $sequence_8 = { 6808020000 8d85e4fcffff 53 50 e8???????? 6804010000 8d85ecfeffff }
            // n = 7, score = 100
            //   6808020000           | push                0x208
            //   8d85e4fcffff         | lea                 eax, [ebp - 0x31c]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   6804010000           | push                0x104
            //   8d85ecfeffff         | lea                 eax, [ebp - 0x114]

        $sequence_9 = { eb13 68???????? eb0c 68???????? eb05 68???????? 8d85e4f7ffff }
            // n = 7, score = 100
            //   eb13                 | jmp                 0x15
            //   68????????           |                     
            //   eb0c                 | jmp                 0xe
            //   68????????           |                     
            //   eb05                 | jmp                 7
            //   68????????           |                     
            //   8d85e4f7ffff         | lea                 eax, [ebp - 0x81c]

    condition:
        7 of them and filesize < 360448
}