rule win_fanny_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.fanny."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fanny"
        malpedia_rule_date = "20220405"
        malpedia_hash = "ecd38294bd47d5589be5cd5490dc8bb4804afc2a"
        malpedia_version = ""
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
        $sequence_0 = { 750e 8b45c8 0fb64802 83f925 7502 eb05 }
            // n = 6, score = 200
            //   750e                 | jne                 0x10
            //   8b45c8               | mov                 eax, dword ptr [ebp - 0x38]
            //   0fb64802             | movzx               ecx, byte ptr [eax + 2]
            //   83f925               | cmp                 ecx, 0x25
            //   7502                 | jne                 4
            //   eb05                 | jmp                 7

        $sequence_1 = { ffd3 59 ff75e4 ffd3 59 33ff 83450c02 }
            // n = 7, score = 200
            //   ffd3                 | call                ebx
            //   59                   | pop                 ecx
            //   ff75e4               | push                dword ptr [ebp - 0x1c]
            //   ffd3                 | call                ebx
            //   59                   | pop                 ecx
            //   33ff                 | xor                 edi, edi
            //   83450c02             | add                 dword ptr [ebp + 0xc], 2

        $sequence_2 = { 897e18 3bc7 750a c74620a0354000 }
            // n = 4, score = 200
            //   897e18               | mov                 dword ptr [esi + 0x18], edi
            //   3bc7                 | cmp                 eax, edi
            //   750a                 | jne                 0xc
            //   c74620a0354000       | mov                 dword ptr [esi + 0x20], 0x4035a0

        $sequence_3 = { 83bdd4fdffff00 740d 8b8dd4fdffff 51 ff15???????? 8b45f8 }
            // n = 6, score = 200
            //   83bdd4fdffff00       | cmp                 dword ptr [ebp - 0x22c], 0
            //   740d                 | je                  0xf
            //   8b8dd4fdffff         | mov                 ecx, dword ptr [ebp - 0x22c]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

        $sequence_4 = { 50 6aff 680d100000 56 8b3d???????? ffd7 8945e4 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   6aff                 | push                -1
            //   680d100000           | push                0x100d
            //   56                   | push                esi
            //   8b3d????????         |                     
            //   ffd7                 | call                edi
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax

        $sequence_5 = { 751f c745bc00000000 8d4dec e8???????? 8d4dd8 e8???????? 8b45bc }
            // n = 7, score = 200
            //   751f                 | jne                 0x21
            //   c745bc00000000       | mov                 dword ptr [ebp - 0x44], 0
            //   8d4dec               | lea                 ecx, dword ptr [ebp - 0x14]
            //   e8????????           |                     
            //   8d4dd8               | lea                 ecx, dword ptr [ebp - 0x28]
            //   e8????????           |                     
            //   8b45bc               | mov                 eax, dword ptr [ebp - 0x44]

        $sequence_6 = { 50 e8???????? 59 c745fc01000000 83c609 4f }
            // n = 6, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   83c609               | add                 esi, 9
            //   4f                   | dec                 edi

        $sequence_7 = { 8d44240c 83e103 50 f3a4 8d4c2420 8d942468010000 }
            // n = 6, score = 200
            //   8d44240c             | lea                 eax, dword ptr [esp + 0xc]
            //   83e103               | and                 ecx, 3
            //   50                   | push                eax
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8d4c2420             | lea                 ecx, dword ptr [esp + 0x20]
            //   8d942468010000       | lea                 edx, dword ptr [esp + 0x168]

        $sequence_8 = { 6a00 e8???????? 59 c3 ff35???????? ff15???????? ff35???????? }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   ff35????????         |                     

        $sequence_9 = { e8???????? 83c404 8bf0 81ff04010000 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8bf0                 | mov                 esi, eax
            //   81ff04010000         | cmp                 edi, 0x104

        $sequence_10 = { 51 8d8514020000 52 50 57 ff15???????? 85c0 }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   8d8514020000         | lea                 eax, dword ptr [ebp + 0x214]
            //   52                   | push                edx
            //   50                   | push                eax
            //   57                   | push                edi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_11 = { 81f904010000 7364 8bfe 83c9ff f2ae f7d1 49 }
            // n = 7, score = 200
            //   81f904010000         | cmp                 ecx, 0x104
            //   7364                 | jae                 0x66
            //   8bfe                 | mov                 edi, esi
            //   83c9ff               | or                  ecx, 0xffffffff
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx

        $sequence_12 = { 8b450c 894208 8b4dfc c7410c00000000 ff15???????? 8b55fc }
            // n = 6, score = 200
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   894208               | mov                 dword ptr [edx + 8], eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   c7410c00000000       | mov                 dword ptr [ecx + 0xc], 0
            //   ff15????????         |                     
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]

        $sequence_13 = { 85f6 0f84ab010000 a1???????? 8b08 6bc961 }
            // n = 5, score = 200
            //   85f6                 | test                esi, esi
            //   0f84ab010000         | je                  0x1b1
            //   a1????????           |                     
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   6bc961               | imul                ecx, ecx, 0x61

        $sequence_14 = { 66ab aa 8b84242c010000 83780800 0f869b010000 53 6a00 }
            // n = 7, score = 200
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8b84242c010000       | mov                 eax, dword ptr [esp + 0x12c]
            //   83780800             | cmp                 dword ptr [eax + 8], 0
            //   0f869b010000         | jbe                 0x1a1
            //   53                   | push                ebx
            //   6a00                 | push                0

        $sequence_15 = { 33c0 eb40 8b4508 8b4803 }
            // n = 4, score = 200
            //   33c0                 | xor                 eax, eax
            //   eb40                 | jmp                 0x42
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b4803               | mov                 ecx, dword ptr [eax + 3]

    condition:
        7 of them and filesize < 368640
}