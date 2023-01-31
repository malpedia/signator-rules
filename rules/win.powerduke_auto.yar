rule win_powerduke_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.powerduke."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.powerduke"
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
        $sequence_0 = { 0345cc 8b4dc8 8d55c8 52 51 50 }
            // n = 6, score = 500
            //   0345cc               | add                 eax, dword ptr [ebp - 0x34]
            //   8b4dc8               | mov                 ecx, dword ptr [ebp - 0x38]
            //   8d55c8               | lea                 edx, [ebp - 0x38]
            //   52                   | push                edx
            //   51                   | push                ecx
            //   50                   | push                eax

        $sequence_1 = { 50 6a00 6a00 51 ffb5f8fbffff }
            // n = 5, score = 500
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   ffb5f8fbffff         | push                dword ptr [ebp - 0x408]

        $sequence_2 = { 8b45c8 09c0 7434 0345cc 3b4518 }
            // n = 5, score = 500
            //   8b45c8               | mov                 eax, dword ptr [ebp - 0x38]
            //   09c0                 | or                  eax, eax
            //   7434                 | je                  0x36
            //   0345cc               | add                 eax, dword ptr [ebp - 0x34]
            //   3b4518               | cmp                 eax, dword ptr [ebp + 0x18]

        $sequence_3 = { 31c0 eb19 8b4f24 01d9 0fb71451 8b4f1c 01d9 }
            // n = 7, score = 500
            //   31c0                 | xor                 eax, eax
            //   eb19                 | jmp                 0x1b
            //   8b4f24               | mov                 ecx, dword ptr [edi + 0x24]
            //   01d9                 | add                 ecx, ebx
            //   0fb71451             | movzx               edx, word ptr [ecx + edx*2]
            //   8b4f1c               | mov                 ecx, dword ptr [edi + 0x1c]
            //   01d9                 | add                 ecx, ebx

        $sequence_4 = { 6a00 6a00 6a00 6a00 ff75c4 ff15???????? 09c0 }
            // n = 7, score = 500
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff75c4               | push                dword ptr [ebp - 0x3c]
            //   ff15????????         |                     
            //   09c0                 | or                  eax, eax

        $sequence_5 = { 0f8579010000 89f7 31c9 803c0f3a 7409 }
            // n = 5, score = 500
            //   0f8579010000         | jne                 0x17f
            //   89f7                 | mov                 edi, esi
            //   31c9                 | xor                 ecx, ecx
            //   803c0f3a             | cmp                 byte ptr [edi + ecx], 0x3a
            //   7409                 | je                  0xb

        $sequence_6 = { 7409 42 39ca 75e6 31c0 eb19 }
            // n = 6, score = 500
            //   7409                 | je                  0xb
            //   42                   | inc                 edx
            //   39ca                 | cmp                 edx, ecx
            //   75e6                 | jne                 0xffffffe8
            //   31c0                 | xor                 eax, eax
            //   eb19                 | jmp                 0x1b

        $sequence_7 = { ff15???????? 09c0 0f8493000000 c745f901000000 89c3 be???????? 89f7 }
            // n = 7, score = 500
            //   ff15????????         |                     
            //   09c0                 | or                  eax, eax
            //   0f8493000000         | je                  0x99
            //   c745f901000000       | mov                 dword ptr [ebp - 7], 1
            //   89c3                 | mov                 ebx, eax
            //   be????????           |                     
            //   89f7                 | mov                 edi, esi

        $sequence_8 = { 4e 4f e2f2 5f 5e }
            // n = 5, score = 500
            //   4e                   | dec                 esi
            //   4f                   | dec                 edi
            //   e2f2                 | loop                0xfffffff4
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_9 = { e8???????? eb0b 8b4d0c c70100000000 eb05 8b4d0c }
            // n = 6, score = 500
            //   e8????????           |                     
            //   eb0b                 | jmp                 0xd
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   c70100000000         | mov                 dword ptr [ecx], 0
            //   eb05                 | jmp                 7
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]

    condition:
        7 of them and filesize < 57344
}