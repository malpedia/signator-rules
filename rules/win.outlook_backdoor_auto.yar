rule win_outlook_backdoor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.outlook_backdoor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.outlook_backdoor"
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
        $sequence_0 = { 85c0 75e1 807df700 0f94c0 22d8 885df6 }
            // n = 6, score = 600
            //   85c0                 | test                eax, eax
            //   75e1                 | jne                 0xffffffe3
            //   807df700             | cmp                 byte ptr [ebp - 9], 0
            //   0f94c0               | sete                al
            //   22d8                 | and                 bl, al
            //   885df6               | mov                 byte ptr [ebp - 0xa], bl

        $sequence_1 = { ff15???????? 85c0 7505 e8???????? 57 ff15???????? ff75f0 }
            // n = 7, score = 600
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7
            //   e8????????           |                     
            //   57                   | push                edi
            //   ff15????????         |                     
            //   ff75f0               | push                dword ptr [ebp - 0x10]

        $sequence_2 = { e8???????? 8d7758 e8???????? c6477400 8bc7 5e c3 }
            // n = 7, score = 600
            //   e8????????           |                     
            //   8d7758               | lea                 esi, [edi + 0x58]
            //   e8????????           |                     
            //   c6477400             | mov                 byte ptr [edi + 0x74], 0
            //   8bc7                 | mov                 eax, edi
            //   5e                   | pop                 esi
            //   c3                   | ret                 

        $sequence_3 = { ff5104 8b45f0 c745ec01000000 c645fc01 3bc3 7406 8b08 }
            // n = 7, score = 600
            //   ff5104               | call                dword ptr [ecx + 4]
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   c745ec01000000       | mov                 dword ptr [ebp - 0x14], 1
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   3bc3                 | cmp                 eax, ebx
            //   7406                 | je                  8
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_4 = { 8b4e08 e8???????? 8b36 03d8 3b771c 75ec 5e }
            // n = 7, score = 600
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]
            //   e8????????           |                     
            //   8b36                 | mov                 esi, dword ptr [esi]
            //   03d8                 | add                 ebx, eax
            //   3b771c               | cmp                 esi, dword ptr [edi + 0x1c]
            //   75ec                 | jne                 0xffffffee
            //   5e                   | pop                 esi

        $sequence_5 = { e8???????? 834dfcff 56 6a01 8d75d4 e8???????? 8b450c }
            // n = 7, score = 600
            //   e8????????           |                     
            //   834dfcff             | or                  dword ptr [ebp - 4], 0xffffffff
            //   56                   | push                esi
            //   6a01                 | push                1
            //   8d75d4               | lea                 esi, [ebp - 0x2c]
            //   e8????????           |                     
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_6 = { 50 56 53 53 ff15???????? ff742410 8d4c2420 }
            // n = 7, score = 600
            //   50                   | push                eax
            //   56                   | push                esi
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   ff742410             | push                dword ptr [esp + 0x10]
            //   8d4c2420             | lea                 ecx, [esp + 0x20]

        $sequence_7 = { eb02 33f6 8b4010 25c0010000 83f840 745d 3d00010000 }
            // n = 7, score = 600
            //   eb02                 | jmp                 4
            //   33f6                 | xor                 esi, esi
            //   8b4010               | mov                 eax, dword ptr [eax + 0x10]
            //   25c0010000           | and                 eax, 0x1c0
            //   83f840               | cmp                 eax, 0x40
            //   745d                 | je                  0x5f
            //   3d00010000           | cmp                 eax, 0x100

        $sequence_8 = { 8b30 8b7804 8b4d08 8d442410 e8???????? 57 8b7d08 }
            // n = 7, score = 600
            //   8b30                 | mov                 esi, dword ptr [eax]
            //   8b7804               | mov                 edi, dword ptr [eax + 4]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   e8????????           |                     
            //   57                   | push                edi
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]

        $sequence_9 = { e8???????? 84c0 7422 837f1810 7205 8b4704 eb03 }
            // n = 7, score = 600
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7422                 | je                  0x24
            //   837f1810             | cmp                 dword ptr [edi + 0x18], 0x10
            //   7205                 | jb                  7
            //   8b4704               | mov                 eax, dword ptr [edi + 4]
            //   eb03                 | jmp                 5

    condition:
        7 of them and filesize < 2912256
}