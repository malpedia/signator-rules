rule win_c0d0so0_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.c0d0so0."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.c0d0so0"
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
        $sequence_0 = { 895dfc 8975f4 ff15???????? ff75f8 }
            // n = 4, score = 600
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   8975f4               | mov                 dword ptr [ebp - 0xc], esi
            //   ff15????????         |                     
            //   ff75f8               | push                dword ptr [ebp - 8]

        $sequence_1 = { 7404 0006 eb02 2806 0fb6c0 03d0 03f0 }
            // n = 7, score = 600
            //   7404                 | je                  6
            //   0006                 | add                 byte ptr [esi], al
            //   eb02                 | jmp                 4
            //   2806                 | sub                 byte ptr [esi], al
            //   0fb6c0               | movzx               eax, al
            //   03d0                 | add                 edx, eax
            //   03f0                 | add                 esi, eax

        $sequence_2 = { 807e0d00 c6460801 7469 8b460e 8b1d???????? 8365f800 83c012 }
            // n = 7, score = 600
            //   807e0d00             | cmp                 byte ptr [esi + 0xd], 0
            //   c6460801             | mov                 byte ptr [esi + 8], 1
            //   7469                 | je                  0x6b
            //   8b460e               | mov                 eax, dword ptr [esi + 0xe]
            //   8b1d????????         |                     
            //   8365f800             | and                 dword ptr [ebp - 8], 0
            //   83c012               | add                 eax, 0x12

        $sequence_3 = { 53 8b5f04 c745f401000000 0f86f4000000 56 8bb080000000 6a14 }
            // n = 7, score = 600
            //   53                   | push                ebx
            //   8b5f04               | mov                 ebx, dword ptr [edi + 4]
            //   c745f401000000       | mov                 dword ptr [ebp - 0xc], 1
            //   0f86f4000000         | jbe                 0xfa
            //   56                   | push                esi
            //   8bb080000000         | mov                 esi, dword ptr [eax + 0x80]
            //   6a14                 | push                0x14

        $sequence_4 = { 83c204 83f914 7ceb 8bc7 8b4dfc 33cd }
            // n = 6, score = 600
            //   83c204               | add                 edx, 4
            //   83f914               | cmp                 ecx, 0x14
            //   7ceb                 | jl                  0xffffffed
            //   8bc7                 | mov                 eax, edi
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   33cd                 | xor                 ecx, ebp

        $sequence_5 = { 752c 6a01 56 e8???????? 59 59 }
            // n = 6, score = 600
            //   752c                 | jne                 0x2e
            //   6a01                 | push                1
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx

        $sequence_6 = { 50 33ff ff15???????? 8d4598 50 ff15???????? }
            // n = 6, score = 600
            //   50                   | push                eax
            //   33ff                 | xor                 edi, edi
            //   ff15????????         |                     
            //   8d4598               | lea                 eax, [ebp - 0x68]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_7 = { ff7334 ffd6 8945fc 85c0 }
            // n = 4, score = 600
            //   ff7334               | push                dword ptr [ebx + 0x34]
            //   ffd6                 | call                esi
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   85c0                 | test                eax, eax

        $sequence_8 = { 3acb 75f6 8bc7 5f 5e }
            // n = 5, score = 600
            //   3acb                 | cmp                 cl, bl
            //   75f6                 | jne                 0xfffffff8
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_9 = { 33ff 53 47 e8???????? 59 eb0b 56 }
            // n = 7, score = 600
            //   33ff                 | xor                 edi, edi
            //   53                   | push                ebx
            //   47                   | inc                 edi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   eb0b                 | jmp                 0xd
            //   56                   | push                esi

    condition:
        7 of them and filesize < 450560
}