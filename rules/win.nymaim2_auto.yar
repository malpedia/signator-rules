rule win_nymaim2_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.nymaim2."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nymaim2"
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
        $sequence_0 = { 6a19 8d4dcc c645fc07 e8???????? ff75f0 8bc8 c645fc08 }
            // n = 7, score = 200
            //   6a19                 | push                0x19
            //   8d4dcc               | lea                 ecx, [ebp - 0x34]
            //   c645fc07             | mov                 byte ptr [ebp - 4], 7
            //   e8????????           |                     
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   8bc8                 | mov                 ecx, eax
            //   c645fc08             | mov                 byte ptr [ebp - 4], 8

        $sequence_1 = { 8b7dec c1e704 03fe 038f94c90000 039798c90000 8b7d08 0fb77c7b06 }
            // n = 7, score = 200
            //   8b7dec               | mov                 edi, dword ptr [ebp - 0x14]
            //   c1e704               | shl                 edi, 4
            //   03fe                 | add                 edi, esi
            //   038f94c90000         | add                 ecx, dword ptr [edi + 0xc994]
            //   039798c90000         | add                 edx, dword ptr [edi + 0xc998]
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   0fb77c7b06           | movzx               edi, word ptr [ebx + edi*2 + 6]

        $sequence_2 = { 3bc8 7420 8d4110 83c10c 50 51 8b4d08 }
            // n = 7, score = 200
            //   3bc8                 | cmp                 ecx, eax
            //   7420                 | je                  0x22
            //   8d4110               | lea                 eax, [ecx + 0x10]
            //   83c10c               | add                 ecx, 0xc
            //   50                   | push                eax
            //   51                   | push                ecx
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]

        $sequence_3 = { c645fc01 e8???????? 8bc7 8b4df4 5f 64890d00000000 }
            // n = 6, score = 200
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   e8????????           |                     
            //   8bc7                 | mov                 eax, edi
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   5f                   | pop                 edi
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx

        $sequence_4 = { 0fb74c7b36 03c8 ff048e 8d0c8e 0fb74c7b38 03c8 ff048e }
            // n = 7, score = 200
            //   0fb74c7b36           | movzx               ecx, word ptr [ebx + edi*2 + 0x36]
            //   03c8                 | add                 ecx, eax
            //   ff048e               | inc                 dword ptr [esi + ecx*4]
            //   8d0c8e               | lea                 ecx, [esi + ecx*4]
            //   0fb74c7b38           | movzx               ecx, word ptr [ebx + edi*2 + 0x38]
            //   03c8                 | add                 ecx, eax
            //   ff048e               | inc                 dword ptr [esi + ecx*4]

        $sequence_5 = { e8???????? 33db 8945e8 3bc3 7549 8a450b 53 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   33db                 | xor                 ebx, ebx
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   3bc3                 | cmp                 eax, ebx
            //   7549                 | jne                 0x4b
            //   8a450b               | mov                 al, byte ptr [ebp + 0xb]
            //   53                   | push                ebx

        $sequence_6 = { ff4804 8b06 ff4008 8b06 83780800 0f854affffff ff400c }
            // n = 7, score = 200
            //   ff4804               | dec                 dword ptr [eax + 4]
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   ff4008               | inc                 dword ptr [eax + 8]
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   83780800             | cmp                 dword ptr [eax + 8], 0
            //   0f854affffff         | jne                 0xffffff50
            //   ff400c               | inc                 dword ptr [eax + 0xc]

        $sequence_7 = { e8???????? e9???????? 8bce e8???????? 84c0 756c 6a01 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   e9????????           |                     
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   756c                 | jne                 0x6e
            //   6a01                 | push                1

        $sequence_8 = { 5b 64890d00000000 c9 c20800 56 8bf1 8d4e04 }
            // n = 7, score = 200
            //   5b                   | pop                 ebx
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   c9                   | leave               
            //   c20800               | ret                 8
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   8d4e04               | lea                 ecx, [esi + 4]

        $sequence_9 = { e8???????? 46 3b7514 7ca8 6a10 5a 33c9 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   46                   | inc                 esi
            //   3b7514               | cmp                 esi, dword ptr [ebp + 0x14]
            //   7ca8                 | jl                  0xffffffaa
            //   6a10                 | push                0x10
            //   5a                   | pop                 edx
            //   33c9                 | xor                 ecx, ecx

    condition:
        7 of them and filesize < 753664
}