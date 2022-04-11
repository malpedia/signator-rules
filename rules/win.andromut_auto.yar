rule win_andromut_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.andromut."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.andromut"
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
        $sequence_0 = { c7859cdfffff00200000 e8???????? 8d8d9cdfffff 51 8d8da4dfffff 51 }
            // n = 6, score = 200
            //   c7859cdfffff00200000     | mov    dword ptr [ebp - 0x2064], 0x2000
            //   e8????????           |                     
            //   8d8d9cdfffff         | lea                 ecx, dword ptr [ebp - 0x2064]
            //   51                   | push                ecx
            //   8d8da4dfffff         | lea                 ecx, dword ptr [ebp - 0x205c]
            //   51                   | push                ecx

        $sequence_1 = { 8d45c8 d1f9 51 57 50 e8???????? 83c40c }
            // n = 7, score = 200
            //   8d45c8               | lea                 eax, dword ptr [ebp - 0x38]
            //   d1f9                 | sar                 ecx, 1
            //   51                   | push                ecx
            //   57                   | push                edi
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_2 = { 51 ffd0 8b9558e0ffff 8d8db8ebffff e8???????? b974728dc4 e8???????? }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   ffd0                 | call                eax
            //   8b9558e0ffff         | mov                 edx, dword ptr [ebp - 0x1fa8]
            //   8d8db8ebffff         | lea                 ecx, dword ptr [ebp - 0x1448]
            //   e8????????           |                     
            //   b974728dc4           | mov                 ecx, 0xc48d7274
            //   e8????????           |                     

        $sequence_3 = { ffd0 85c0 745c 6aff ffb5a8fbffff }
            // n = 5, score = 200
            //   ffd0                 | call                eax
            //   85c0                 | test                eax, eax
            //   745c                 | je                  0x5e
            //   6aff                 | push                -1
            //   ffb5a8fbffff         | push                dword ptr [ebp - 0x458]

        $sequence_4 = { 0bc1 66894455a4 42 83fa2c 72c5 b9883f4e3f e8???????? }
            // n = 7, score = 200
            //   0bc1                 | or                  eax, ecx
            //   66894455a4           | mov                 word ptr [ebp + edx*2 - 0x5c], ax
            //   42                   | inc                 edx
            //   83fa2c               | cmp                 edx, 0x2c
            //   72c5                 | jb                  0xffffffc7
            //   b9883f4e3f           | mov                 ecx, 0x3f4e3f88
            //   e8????????           |                     

        $sequence_5 = { 51 53 50 e8???????? bf05010000 8d85a8f9ffff 57 }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   bf05010000           | mov                 edi, 0x105
            //   8d85a8f9ffff         | lea                 eax, dword ptr [ebp - 0x658]
            //   57                   | push                edi

        $sequence_6 = { 8d85e0feffff 50 e8???????? 83c40c 89b5e0feffff 8d85e0feffff }
            // n = 6, score = 200
            //   8d85e0feffff         | lea                 eax, dword ptr [ebp - 0x120]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   89b5e0feffff         | mov                 dword ptr [ebp - 0x120], esi
            //   8d85e0feffff         | lea                 eax, dword ptr [ebp - 0x120]

        $sequence_7 = { 889db0e2ffff 68???????? 8d8d38e2ffff 895dfc e8???????? 6a0f }
            // n = 6, score = 200
            //   889db0e2ffff         | mov                 byte ptr [ebp - 0x1d50], bl
            //   68????????           |                     
            //   8d8d38e2ffff         | lea                 ecx, dword ptr [ebp - 0x1dc8]
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   e8????????           |                     
            //   6a0f                 | push                0xf

        $sequence_8 = { a1???????? 33c5 8945fc 56 57 b86edf0000 c745d0c0de6ade }
            // n = 7, score = 200
            //   a1????????           |                     
            //   33c5                 | xor                 eax, ebp
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   56                   | push                esi
            //   57                   | push                edi
            //   b86edf0000           | mov                 eax, 0xdf6e
            //   c745d0c0de6ade       | mov                 dword ptr [ebp - 0x30], 0xde6adec0

        $sequence_9 = { 8bc8 03c0 c1e90f 83e101 0bc1 25ffff0000 48 }
            // n = 7, score = 200
            //   8bc8                 | mov                 ecx, eax
            //   03c0                 | add                 eax, eax
            //   c1e90f               | shr                 ecx, 0xf
            //   83e101               | and                 ecx, 1
            //   0bc1                 | or                  eax, ecx
            //   25ffff0000           | and                 eax, 0xffff
            //   48                   | dec                 eax

    condition:
        7 of them and filesize < 368640
}