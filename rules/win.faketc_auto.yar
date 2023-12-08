rule win_faketc_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.faketc."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.faketc"
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
        $sequence_0 = { e8???????? c684248001000002 8b442448 8b5004 8bce ffd2 84c0 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   c684248001000002     | mov                 byte ptr [esp + 0x180], 2
            //   8b442448             | mov                 eax, dword ptr [esp + 0x48]
            //   8b5004               | mov                 edx, dword ptr [eax + 4]
            //   8bce                 | mov                 ecx, esi
            //   ffd2                 | call                edx
            //   84c0                 | test                al, al

        $sequence_1 = { e8???????? 83c410 6a5e 8d8576f7ffff 50 6a00 6a00 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   6a5e                 | push                0x5e
            //   8d8576f7ffff         | lea                 eax, [ebp - 0x88a]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_2 = { 899158010000 8b4508 8b484c 8b55f8 668b4104 66894248 8b4df8 }
            // n = 7, score = 100
            //   899158010000         | mov                 dword ptr [ecx + 0x158], edx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b484c               | mov                 ecx, dword ptr [eax + 0x4c]
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   668b4104             | mov                 ax, word ptr [ecx + 4]
            //   66894248             | mov                 word ptr [edx + 0x48], ax
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]

        $sequence_3 = { e8???????? 83c410 6a00 8b4d8c 51 6a01 8b5508 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   6a00                 | push                0
            //   8b4d8c               | mov                 ecx, dword ptr [ebp - 0x74]
            //   51                   | push                ecx
            //   6a01                 | push                1
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]

        $sequence_4 = { ffd6 50 b86f000000 e8???????? 83c404 a3???????? eb06 }
            // n = 7, score = 100
            //   ffd6                 | call                esi
            //   50                   | push                eax
            //   b86f000000           | mov                 eax, 0x6f
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   a3????????           |                     
            //   eb06                 | jmp                 8

        $sequence_5 = { e9???????? 8d45d8 50 e8???????? c3 8d8548ffffff 50 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8d45d8               | lea                 eax, [ebp - 0x28]
            //   50                   | push                eax
            //   e8????????           |                     
            //   c3                   | ret                 
            //   8d8548ffffff         | lea                 eax, [ebp - 0xb8]
            //   50                   | push                eax

        $sequence_6 = { c1fa04 8bc2 c1e81f 03c2 895c2410 0f842b010000 895c241c }
            // n = 7, score = 100
            //   c1fa04               | sar                 edx, 4
            //   8bc2                 | mov                 eax, edx
            //   c1e81f               | shr                 eax, 0x1f
            //   03c2                 | add                 eax, edx
            //   895c2410             | mov                 dword ptr [esp + 0x10], ebx
            //   0f842b010000         | je                  0x131
            //   895c241c             | mov                 dword ptr [esp + 0x1c], ebx

        $sequence_7 = { e8???????? 8b85b0fdffff 8b0d???????? 8d95b8fdffff 52 68???????? 50 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b85b0fdffff         | mov                 eax, dword ptr [ebp - 0x250]
            //   8b0d????????         |                     
            //   8d95b8fdffff         | lea                 edx, [ebp - 0x248]
            //   52                   | push                edx
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_8 = { e8???????? b917000000 8bf0 bf???????? f3a5 66a5 c745fc02000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   b917000000           | mov                 ecx, 0x17
            //   8bf0                 | mov                 esi, eax
            //   bf????????           |                     
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   66a5                 | movsw               word ptr es:[edi], word ptr [esi]
            //   c745fc02000000       | mov                 dword ptr [ebp - 4], 2

        $sequence_9 = { c745fc???????? c745f805000000 eb0e c745fc???????? c745f806000000 8b4d08 8b91fc030000 }
            // n = 7, score = 100
            //   c745fc????????       |                     
            //   c745f805000000       | mov                 dword ptr [ebp - 8], 5
            //   eb0e                 | jmp                 0x10
            //   c745fc????????       |                     
            //   c745f806000000       | mov                 dword ptr [ebp - 8], 6
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b91fc030000         | mov                 edx, dword ptr [ecx + 0x3fc]

    condition:
        7 of them and filesize < 6864896
}