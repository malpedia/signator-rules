rule win_darkrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.darkrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkrat"
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
        $sequence_0 = { 2bca 3bc1 0f42c8 837f1410 8bc7 }
            // n = 5, score = 200
            //   2bca                 | sub                 ecx, edx
            //   3bc1                 | cmp                 eax, ecx
            //   0f42c8               | cmovb               ecx, eax
            //   837f1410             | cmp                 dword ptr [edi + 0x14], 0x10
            //   8bc7                 | mov                 eax, edi

        $sequence_1 = { 3bc1 0f8254010000 8bfb 83cf0f 81ffffffff7f }
            // n = 5, score = 200
            //   3bc1                 | cmp                 eax, ecx
            //   0f8254010000         | jb                  0x15a
            //   8bfb                 | mov                 edi, ebx
            //   83cf0f               | or                  edi, 0xf
            //   81ffffffff7f         | cmp                 edi, 0x7fffffff

        $sequence_2 = { 64a300000000 8bf1 8975ec 8975ec 8d4dec }
            // n = 5, score = 200
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8bf1                 | mov                 esi, ecx
            //   8975ec               | mov                 dword ptr [ebp - 0x14], esi
            //   8975ec               | mov                 dword ptr [ebp - 0x14], esi
            //   8d4dec               | lea                 ecx, [ebp - 0x14]

        $sequence_3 = { 8d45f4 64a300000000 8bd9 895dd0 c745fc00000000 895db4 }
            // n = 6, score = 200
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8bd9                 | mov                 ebx, ecx
            //   895dd0               | mov                 dword ptr [ebp - 0x30], ebx
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   895db4               | mov                 dword ptr [ebp - 0x4c], ebx

        $sequence_4 = { 5d c3 8b45f8 837a1410 7202 8b12 3bc8 }
            // n = 7, score = 200
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   837a1410             | cmp                 dword ptr [edx + 0x14], 0x10
            //   7202                 | jb                  4
            //   8b12                 | mov                 edx, dword ptr [edx]
            //   3bc8                 | cmp                 ecx, eax

        $sequence_5 = { b805000000 2bd6 8a0e 8d7601 884c32ff }
            // n = 5, score = 200
            //   b805000000           | mov                 eax, 5
            //   2bd6                 | sub                 edx, esi
            //   8a0e                 | mov                 cl, byte ptr [esi]
            //   8d7601               | lea                 esi, [esi + 1]
            //   884c32ff             | mov                 byte ptr [edx + esi - 1], cl

        $sequence_6 = { 8b75c4 8b08 894d0c 8b4004 50 51 }
            // n = 6, score = 200
            //   8b75c4               | mov                 esi, dword ptr [ebp - 0x3c]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   894d0c               | mov                 dword ptr [ebp + 0xc], ecx
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   50                   | push                eax
            //   51                   | push                ecx

        $sequence_7 = { 8d55b8 837dcc10 8b75b8 8b4314 0f43d6 }
            // n = 5, score = 200
            //   8d55b8               | lea                 edx, [ebp - 0x48]
            //   837dcc10             | cmp                 dword ptr [ebp - 0x34], 0x10
            //   8b75b8               | mov                 esi, dword ptr [ebp - 0x48]
            //   8b4314               | mov                 eax, dword ptr [ebx + 0x14]
            //   0f43d6               | cmovae              edx, esi

        $sequence_8 = { 6a00 c745d400000000 e8???????? 50 e8???????? 83c408 c745e800000000 }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   c745d400000000       | mov                 dword ptr [ebp - 0x2c], 0
            //   e8????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   c745e800000000       | mov                 dword ptr [ebp - 0x18], 0

        $sequence_9 = { 3bc6 724a 837dfc10 7202 8b3f }
            // n = 5, score = 200
            //   3bc6                 | cmp                 eax, esi
            //   724a                 | jb                  0x4c
            //   837dfc10             | cmp                 dword ptr [ebp - 4], 0x10
            //   7202                 | jb                  4
            //   8b3f                 | mov                 edi, dword ptr [edi]

    condition:
        7 of them and filesize < 884736
}