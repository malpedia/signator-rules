rule win_unidentified_089_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-29"
        version = "1"
        description = "Detects win.unidentified_089."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_089"
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
        $sequence_0 = { 83c410 8d5101 8a01 41 84c0 75f9 eb23 }
            // n = 7, score = 300
            //   83c410               | add                 esp, 0x10
            //   8d5101               | lea                 edx, [ecx + 1]
            //   8a01                 | mov                 al, byte ptr [ecx]
            //   41                   | inc                 ecx
            //   84c0                 | test                al, al
            //   75f9                 | jne                 0xfffffffb
            //   eb23                 | jmp                 0x25

        $sequence_1 = { 84c0 75f9 2bca 8d85f0feffff 51 51 }
            // n = 6, score = 300
            //   84c0                 | test                al, al
            //   75f9                 | jne                 0xfffffffb
            //   2bca                 | sub                 ecx, edx
            //   8d85f0feffff         | lea                 eax, [ebp - 0x110]
            //   51                   | push                ecx
            //   51                   | push                ecx

        $sequence_2 = { 0fb7410c 50 0fb7410e 50 }
            // n = 4, score = 300
            //   0fb7410c             | movzx               eax, word ptr [ecx + 0xc]
            //   50                   | push                eax
            //   0fb7410e             | movzx               eax, word ptr [ecx + 0xe]
            //   50                   | push                eax

        $sequence_3 = { 7726 8d3400 8945e0 56 51 8d45d0 50 }
            // n = 7, score = 300
            //   7726                 | ja                  0x28
            //   8d3400               | lea                 esi, [eax + eax]
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   56                   | push                esi
            //   51                   | push                ecx
            //   8d45d0               | lea                 eax, [ebp - 0x30]
            //   50                   | push                eax

        $sequence_4 = { 3bd8 0f42d8 895dfc 8d4301 3dffffff7f 0f87a3000000 }
            // n = 6, score = 300
            //   3bd8                 | cmp                 ebx, eax
            //   0f42d8               | cmovb               ebx, eax
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   8d4301               | lea                 eax, [ebx + 1]
            //   3dffffff7f           | cmp                 eax, 0x7fffffff
            //   0f87a3000000         | ja                  0xa9

        $sequence_5 = { 8918 8b4d98 33d2 c745e000000000 }
            // n = 4, score = 300
            //   8918                 | mov                 dword ptr [eax], ebx
            //   8b4d98               | mov                 ecx, dword ptr [ebp - 0x68]
            //   33d2                 | xor                 edx, edx
            //   c745e000000000       | mov                 dword ptr [ebp - 0x20], 0

        $sequence_6 = { 8b06 81f900100000 7216 8b50fc 83c123 2bc2 }
            // n = 6, score = 300
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   81f900100000         | cmp                 ecx, 0x1000
            //   7216                 | jb                  0x18
            //   8b50fc               | mov                 edx, dword ptr [eax - 4]
            //   83c123               | add                 ecx, 0x23
            //   2bc2                 | sub                 eax, edx

        $sequence_7 = { 83e804 7425 eb26 3df12e0000 741c 3d852f0000 }
            // n = 6, score = 300
            //   83e804               | sub                 eax, 4
            //   7425                 | je                  0x27
            //   eb26                 | jmp                 0x28
            //   3df12e0000           | cmp                 eax, 0x2ef1
            //   741c                 | je                  0x1e
            //   3d852f0000           | cmp                 eax, 0x2f85

    condition:
        7 of them and filesize < 389120
}