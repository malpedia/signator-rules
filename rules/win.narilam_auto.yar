rule win_narilam_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.narilam."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.narilam"
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
        $sequence_0 = { e8???????? 8d953cfeffff 52 8d8534feffff e8???????? 50 ff85f0fdffff }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8d953cfeffff         | lea                 edx, [ebp - 0x1c4]
            //   52                   | push                edx
            //   8d8534feffff         | lea                 eax, [ebp - 0x1cc]
            //   e8????????           |                     
            //   50                   | push                eax
            //   ff85f0fdffff         | inc                 dword ptr [ebp - 0x210]

        $sequence_1 = { ebb9 66b8b302 ebb3 66b8b402 ebad 66b8b502 eba7 }
            // n = 7, score = 100
            //   ebb9                 | jmp                 0xffffffbb
            //   66b8b302             | mov                 ax, 0x2b3
            //   ebb3                 | jmp                 0xffffffb5
            //   66b8b402             | mov                 ax, 0x2b4
            //   ebad                 | jmp                 0xffffffaf
            //   66b8b502             | mov                 ax, 0x2b5
            //   eba7                 | jmp                 0xffffffa9

        $sequence_2 = { 8b55fc 8b83cc000000 ff93c8000000 8b45fc 83785400 7518 8d55f8 }
            // n = 7, score = 100
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8b83cc000000         | mov                 eax, dword ptr [ebx + 0xcc]
            //   ff93c8000000         | call                dword ptr [ebx + 0xc8]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   83785400             | cmp                 dword ptr [eax + 0x54], 0
            //   7518                 | jne                 0x1a
            //   8d55f8               | lea                 edx, [ebp - 8]

        $sequence_3 = { e8???????? 50 8b8678010000 50 8b00 ff5038 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   50                   | push                eax
            //   8b8678010000         | mov                 eax, dword ptr [esi + 0x178]
            //   50                   | push                eax
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   ff5038               | call                dword ptr [eax + 0x38]
            //   e8????????           |                     

        $sequence_4 = { e8???????? 8b45fc e8???????? 8b45fc 8b10 ff92fc000000 8b45fc }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   ff92fc000000         | call                dword ptr [edx + 0xfc]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_5 = { 8b5df8 8b1b 8bc3 83f853 0f8fae000000 0f843b050000 83f816 }
            // n = 7, score = 100
            //   8b5df8               | mov                 ebx, dword ptr [ebp - 8]
            //   8b1b                 | mov                 ebx, dword ptr [ebx]
            //   8bc3                 | mov                 eax, ebx
            //   83f853               | cmp                 eax, 0x53
            //   0f8fae000000         | jg                  0xb4
            //   0f843b050000         | je                  0x541
            //   83f816               | cmp                 eax, 0x16

        $sequence_6 = { a1???????? e8???????? 8b8564ffffff 33c9 5a e8???????? 33f6 }
            // n = 7, score = 100
            //   a1????????           |                     
            //   e8????????           |                     
            //   8b8564ffffff         | mov                 eax, dword ptr [ebp - 0x9c]
            //   33c9                 | xor                 ecx, ecx
            //   5a                   | pop                 edx
            //   e8????????           |                     
            //   33f6                 | xor                 esi, esi

        $sequence_7 = { e8???????? ff8d4cfeffff 8d85c0feffff ba02000000 e8???????? 66c78540feffffa403 ba???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   ff8d4cfeffff         | dec                 dword ptr [ebp - 0x1b4]
            //   8d85c0feffff         | lea                 eax, [ebp - 0x140]
            //   ba02000000           | mov                 edx, 2
            //   e8????????           |                     
            //   66c78540feffffa403     | mov    word ptr [ebp - 0x1c0], 0x3a4
            //   ba????????           |                     

        $sequence_8 = { 8d4dc0 51 e8???????? 59 8bd0 8d45bc e8???????? }
            // n = 7, score = 100
            //   8d4dc0               | lea                 ecx, [ebp - 0x40]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8bd0                 | mov                 edx, eax
            //   8d45bc               | lea                 eax, [ebp - 0x44]
            //   e8????????           |                     

        $sequence_9 = { e8???????? 6a04 8d4c2410 b209 8bc6 e8???????? 83c410 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   6a04                 | push                4
            //   8d4c2410             | lea                 ecx, [esp + 0x10]
            //   b209                 | mov                 dl, 9
            //   8bc6                 | mov                 eax, esi
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10

    condition:
        7 of them and filesize < 3325952
}