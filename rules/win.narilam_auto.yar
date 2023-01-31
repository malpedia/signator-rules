rule win_narilam_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.narilam."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.narilam"
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
        $sequence_0 = { ff8d88feffff 8d459c ba02000000 e8???????? 66c7857cfeffff1001 ba???????? 8d4598 }
            // n = 7, score = 100
            //   ff8d88feffff         | dec                 dword ptr [ebp - 0x178]
            //   8d459c               | lea                 eax, [ebp - 0x64]
            //   ba02000000           | mov                 edx, 2
            //   e8????????           |                     
            //   66c7857cfeffff1001     | mov    word ptr [ebp - 0x184], 0x110
            //   ba????????           |                     
            //   8d4598               | lea                 eax, [ebp - 0x68]

        $sequence_1 = { ff750c ff7508 ffb3ec000000 ffb3e8000000 ffb3f4000000 ffb3f0000000 8bc3 }
            // n = 7, score = 100
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ffb3ec000000         | push                dword ptr [ebx + 0xec]
            //   ffb3e8000000         | push                dword ptr [ebx + 0xe8]
            //   ffb3f4000000         | push                dword ptr [ebx + 0xf4]
            //   ffb3f0000000         | push                dword ptr [ebx + 0xf0]
            //   8bc3                 | mov                 eax, ebx

        $sequence_2 = { e8???????? 8bd0 8d8dfcfeffff 8b4304 8b30 ff9650020000 6a02 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8bd0                 | mov                 edx, eax
            //   8d8dfcfeffff         | lea                 ecx, [ebp - 0x104]
            //   8b4304               | mov                 eax, dword ptr [ebx + 4]
            //   8b30                 | mov                 esi, dword ptr [eax]
            //   ff9650020000         | call                dword ptr [esi + 0x250]
            //   6a02                 | push                2

        $sequence_3 = { b120 e8???????? 7509 33d2 8bc6 e8???????? 8bcb }
            // n = 7, score = 100
            //   b120                 | mov                 cl, 0x20
            //   e8????????           |                     
            //   7509                 | jne                 0xb
            //   33d2                 | xor                 edx, edx
            //   8bc6                 | mov                 eax, esi
            //   e8????????           |                     
            //   8bcb                 | mov                 ecx, ebx

        $sequence_4 = { c78504feffff07000000 eb76 81bd0cfeffff96000000 7e0c c78504feffff06000000 eb5e 83bd0cfeffff64 }
            // n = 7, score = 100
            //   c78504feffff07000000     | mov    dword ptr [ebp - 0x1fc], 7
            //   eb76                 | jmp                 0x78
            //   81bd0cfeffff96000000     | cmp    dword ptr [ebp - 0x1f4], 0x96
            //   7e0c                 | jle                 0xe
            //   c78504feffff06000000     | mov    dword ptr [ebp - 0x1fc], 6
            //   eb5e                 | jmp                 0x60
            //   83bd0cfeffff64       | cmp                 dword ptr [ebp - 0x1f4], 0x64

        $sequence_5 = { eb50 8d4318 33d2 b101 e8???????? eb42 8bc6 }
            // n = 7, score = 100
            //   eb50                 | jmp                 0x52
            //   8d4318               | lea                 eax, [ebx + 0x18]
            //   33d2                 | xor                 edx, edx
            //   b101                 | mov                 cl, 1
            //   e8????????           |                     
            //   eb42                 | jmp                 0x44
            //   8bc6                 | mov                 eax, esi

        $sequence_6 = { 8b8124030000 8b10 ff5244 8b4d08 8b812c030000 8b10 ff5244 }
            // n = 7, score = 100
            //   8b8124030000         | mov                 eax, dword ptr [ecx + 0x324]
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   ff5244               | call                dword ptr [edx + 0x44]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b812c030000         | mov                 eax, dword ptr [ecx + 0x32c]
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   ff5244               | call                dword ptr [edx + 0x44]

        $sequence_7 = { 8b15???????? e8???????? 83c404 8d45f4 50 8b03 50 }
            // n = 7, score = 100
            //   8b15????????         |                     
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   50                   | push                eax

        $sequence_8 = { ff85e8feffff 8d5580 8d45fc e8???????? ff8de8feffff 8d4580 ba02000000 }
            // n = 7, score = 100
            //   ff85e8feffff         | inc                 dword ptr [ebp - 0x118]
            //   8d5580               | lea                 edx, [ebp - 0x80]
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   e8????????           |                     
            //   ff8de8feffff         | dec                 dword ptr [ebp - 0x118]
            //   8d4580               | lea                 eax, [ebp - 0x80]
            //   ba02000000           | mov                 edx, 2

        $sequence_9 = { e8???????? 894588 66c745a00800 8d45fc e8???????? ff45ac 66c745a01400 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   894588               | mov                 dword ptr [ebp - 0x78], eax
            //   66c745a00800         | mov                 word ptr [ebp - 0x60], 8
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   e8????????           |                     
            //   ff45ac               | inc                 dword ptr [ebp - 0x54]
            //   66c745a01400         | mov                 word ptr [ebp - 0x60], 0x14

    condition:
        7 of them and filesize < 3325952
}