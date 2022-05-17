rule win_dadjoke_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.dadjoke."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dadjoke"
        malpedia_rule_date = "20220513"
        malpedia_hash = "7f4b2229e6ae614d86d74917f6d5b41890e62a26"
        malpedia_version = "20220516"
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
        $sequence_0 = { 56 57 6800081000 6a00 }
            // n = 4, score = 500
            //   56                   | push                esi
            //   57                   | push                edi
            //   6800081000           | push                0x100800
            //   6a00                 | push                0

        $sequence_1 = { 6a00 6a00 ff15???????? 6808020000 }
            // n = 4, score = 500
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   6808020000           | push                0x208

        $sequence_2 = { 8b5508 81c228021000 52 e8???????? 8d45e0 }
            // n = 5, score = 400
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   81c228021000         | add                 edx, 0x100228
            //   52                   | push                edx
            //   e8????????           |                     
            //   8d45e0               | lea                 eax, [ebp - 0x20]

        $sequence_3 = { 8b7dc8 8b7584 8b4580 8bc8 }
            // n = 4, score = 400
            //   8b7dc8               | mov                 edi, dword ptr [ebp - 0x38]
            //   8b7584               | mov                 esi, dword ptr [ebp - 0x7c]
            //   8b4580               | mov                 eax, dword ptr [ebp - 0x80]
            //   8bc8                 | mov                 ecx, eax

        $sequence_4 = { 81c106010000 51 8b55b4 52 8b45ec }
            // n = 5, score = 400
            //   81c106010000         | add                 ecx, 0x106
            //   51                   | push                ecx
            //   8b55b4               | mov                 edx, dword ptr [ebp - 0x4c]
            //   52                   | push                edx
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]

        $sequence_5 = { 8b08 51 ff15???????? 8945e0 6a28 }
            // n = 5, score = 400
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   6a28                 | push                0x28

        $sequence_6 = { 8d45a4 50 e8???????? 8d8d30ffffff 51 }
            // n = 5, score = 400
            //   8d45a4               | lea                 eax, [ebp - 0x5c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d8d30ffffff         | lea                 ecx, [ebp - 0xd0]
            //   51                   | push                ecx

        $sequence_7 = { 0f84b4000000 8d9530ffffff 8955e8 8b45e8 83c001 }
            // n = 5, score = 400
            //   0f84b4000000         | je                  0xba
            //   8d9530ffffff         | lea                 edx, [ebp - 0xd0]
            //   8955e8               | mov                 dword ptr [ebp - 0x18], edx
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   83c001               | add                 eax, 1

        $sequence_8 = { 84c0 0f94c1 8bc1 c3 a1???????? c3 8bff }
            // n = 7, score = 300
            //   84c0                 | test                al, al
            //   0f94c1               | sete                cl
            //   8bc1                 | mov                 eax, ecx
            //   c3                   | ret                 
            //   a1????????           |                     
            //   c3                   | ret                 
            //   8bff                 | mov                 edi, edi

        $sequence_9 = { 5e c3 8bff 55 8bec 83ec10 33c0 }
            // n = 7, score = 300
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec10               | sub                 esp, 0x10
            //   33c0                 | xor                 eax, eax

        $sequence_10 = { c3 6a04 e8???????? 59 c3 6a0c }
            // n = 6, score = 300
            //   c3                   | ret                 
            //   6a04                 | push                4
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   6a0c                 | push                0xc

        $sequence_11 = { 6a02 ff15???????? 85c0 7417 b920000000 }
            // n = 5, score = 300
            //   6a02                 | push                2
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7417                 | je                  0x19
            //   b920000000           | mov                 ecx, 0x20

        $sequence_12 = { 8b08 ff5118 8b85e0faffff 50 8b08 ff5108 }
            // n = 6, score = 200
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff5118               | call                dword ptr [ecx + 0x18]
            //   8b85e0faffff         | mov                 eax, dword ptr [ebp - 0x520]
            //   50                   | push                eax
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff5108               | call                dword ptr [ecx + 8]

        $sequence_13 = { 8d85f8feffff 50 ff15???????? 85c0 0f85b5000000 50 ff15???????? }
            // n = 7, score = 200
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f85b5000000         | jne                 0xbb
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_14 = { ff15???????? 85c0 7524 8b35???????? 57 ffd6 }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7524                 | jne                 0x26
            //   8b35????????         |                     
            //   57                   | push                edi
            //   ffd6                 | call                esi

        $sequence_15 = { f2c3 f2e96b030000 55 8bec 8b450c 83e800 }
            // n = 6, score = 200
            // 
            //   f2e96b030000         | bnd jmp             0x371
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   83e800               | sub                 eax, 0

        $sequence_16 = { 2bc6 7411 0f1f440000 0fbe4c15f4 42 03d9 3bd0 }
            // n = 7, score = 200
            //   2bc6                 | sub                 eax, esi
            //   7411                 | je                  0x13
            //   0f1f440000           | nop                 dword ptr [eax + eax]
            //   0fbe4c15f4           | movsx               ecx, byte ptr [ebp + edx - 0xc]
            //   42                   | inc                 edx
            //   03d9                 | add                 ebx, ecx
            //   3bd0                 | cmp                 edx, eax

        $sequence_17 = { 8b85e0faffff 8d95e8faffff 6a01 52 50 }
            // n = 5, score = 200
            //   8b85e0faffff         | mov                 eax, dword ptr [ebp - 0x520]
            //   8d95e8faffff         | lea                 edx, [ebp - 0x518]
            //   6a01                 | push                1
            //   52                   | push                edx
            //   50                   | push                eax

        $sequence_18 = { 6a00 6a00 6a03 6a00 6a00 68???????? e8???????? }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a03                 | push                3
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_19 = { 6683f87f 8d642408 0f856d170000 eb00 f30f7e442404 }
            // n = 5, score = 200
            //   6683f87f             | cmp                 ax, 0x7f
            //   8d642408             | lea                 esp, [esp + 8]
            //   0f856d170000         | jne                 0x1773
            //   eb00                 | jmp                 2
            //   f30f7e442404         | movq                xmm0, qword ptr [esp + 4]

        $sequence_20 = { ffd7 8b45e8 83c004 3bd8 72b9 }
            // n = 5, score = 100
            //   ffd7                 | call                edi
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   83c004               | add                 eax, 4
            //   3bd8                 | cmp                 ebx, eax
            //   72b9                 | jb                  0xffffffbb

        $sequence_21 = { ff75e0 e8???????? 83c408 85c0 0f84cf000000 833d????????00 }
            // n = 6, score = 100
            //   ff75e0               | push                dword ptr [ebp - 0x20]
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   0f84cf000000         | je                  0xd5
            //   833d????????00       |                     

    condition:
        7 of them and filesize < 344064
}