rule win_mimikatz_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.mimikatz."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mimikatz"
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
        $sequence_0 = { f7f1 85d2 7406 2bca }
            // n = 4, score = 300
            //   f7f1                 | div                 ecx
            //   85d2                 | test                edx, edx
            //   7406                 | je                  8
            //   2bca                 | sub                 ecx, edx

        $sequence_1 = { 83f8ff 750e ff15???????? c7002a000000 }
            // n = 4, score = 300
            //   83f8ff               | cmp                 eax, -1
            //   750e                 | jne                 0x10
            //   ff15????????         |                     
            //   c7002a000000         | mov                 dword ptr [eax], 0x2a

        $sequence_2 = { ff5028 8be8 85c0 787a }
            // n = 4, score = 200
            //   ff5028               | call                dword ptr [eax + 0x28]
            //   8be8                 | mov                 ebp, eax
            //   85c0                 | test                eax, eax
            //   787a                 | js                  0x7c

        $sequence_3 = { e8???????? 894720 85c0 7413 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   894720               | mov                 dword ptr [edi + 0x20], eax
            //   85c0                 | test                eax, eax
            //   7413                 | je                  0x15

        $sequence_4 = { c3 81f998000000 7410 81f996000000 7408 81f99b000000 }
            // n = 6, score = 200
            //   c3                   | ret                 
            //   81f998000000         | cmp                 ecx, 0x98
            //   7410                 | je                  0x12
            //   81f996000000         | cmp                 ecx, 0x96
            //   7408                 | je                  0xa
            //   81f99b000000         | cmp                 ecx, 0x9b

        $sequence_5 = { f30f6f4928 f30f7f8c24a0000000 f30f6f4138 f30f7f8424b8000000 }
            // n = 4, score = 200
            //   f30f6f4928           | movdqu              xmm1, xmmword ptr [ecx + 0x28]
            //   f30f7f8c24a0000000     | movdqu    xmmword ptr [esp + 0xa0], xmm1
            //   f30f6f4138           | movdqu              xmm0, xmmword ptr [ecx + 0x38]
            //   f30f7f8424b8000000     | movdqu    xmmword ptr [esp + 0xb8], xmm0

        $sequence_6 = { 83f812 72f1 33c0 c3 }
            // n = 4, score = 200
            //   83f812               | cmp                 eax, 0x12
            //   72f1                 | jb                  0xfffffff3
            //   33c0                 | xor                 eax, eax
            //   c3                   | ret                 

        $sequence_7 = { 6683f83f 7607 32c0 e9???????? }
            // n = 4, score = 200
            //   6683f83f             | cmp                 ax, 0x3f
            //   7607                 | jbe                 9
            //   32c0                 | xor                 al, al
            //   e9????????           |                     

        $sequence_8 = { 3c02 7207 e8???????? eb10 }
            // n = 4, score = 200
            //   3c02                 | cmp                 al, 2
            //   7207                 | jb                  9
            //   e8????????           |                     
            //   eb10                 | jmp                 0x12

        $sequence_9 = { eb0c bfdfff0000 6623fe 6683ef07 8b742474 }
            // n = 5, score = 200
            //   eb0c                 | jmp                 0xe
            //   bfdfff0000           | mov                 edi, 0xffdf
            //   6623fe               | and                 di, si
            //   6683ef07             | sub                 di, 7
            //   8b742474             | mov                 esi, dword ptr [esp + 0x74]

        $sequence_10 = { 2bc1 85c9 7403 83c008 d1e8 }
            // n = 5, score = 200
            //   2bc1                 | sub                 eax, ecx
            //   85c9                 | test                ecx, ecx
            //   7403                 | je                  5
            //   83c008               | add                 eax, 8
            //   d1e8                 | shr                 eax, 1

        $sequence_11 = { 66894108 33c0 39410c 740b }
            // n = 4, score = 200
            //   66894108             | mov                 word ptr [ecx + 8], ax
            //   33c0                 | xor                 eax, eax
            //   39410c               | cmp                 dword ptr [ecx + 0xc], eax
            //   740b                 | je                  0xd

        $sequence_12 = { ff15???????? b940000000 8bd0 89442430 }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   b940000000           | mov                 ecx, 0x40
            //   8bd0                 | mov                 edx, eax
            //   89442430             | mov                 dword ptr [esp + 0x30], eax

        $sequence_13 = { ff15???????? b9e9fd0000 8905???????? ff15???????? }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   b9e9fd0000           | mov                 ecx, 0xfde9
            //   8905????????         |                     
            //   ff15????????         |                     

        $sequence_14 = { c705????????cf2f4000 8935???????? a3???????? ff15???????? a3???????? 83f8ff 0f84c1000000 }
            // n = 7, score = 100
            //   c705????????cf2f4000     |     
            //   8935????????         |                     
            //   a3????????           |                     
            //   ff15????????         |                     
            //   a3????????           |                     
            //   83f8ff               | cmp                 eax, -1
            //   0f84c1000000         | je                  0xc7

        $sequence_15 = { 83e001 51 894614 c7461ce0164000 }
            // n = 4, score = 100
            //   83e001               | and                 eax, 1
            //   51                   | push                ecx
            //   894614               | mov                 dword ptr [esi + 0x14], eax
            //   c7461ce0164000       | mov                 dword ptr [esi + 0x1c], 0x4016e0

        $sequence_16 = { 0f854fffffff 85db 0f84b9000000 83fb04 }
            // n = 4, score = 100
            //   0f854fffffff         | jne                 0xffffff55
            //   85db                 | test                ebx, ebx
            //   0f84b9000000         | je                  0xbf
            //   83fb04               | cmp                 ebx, 4

        $sequence_17 = { c1f805 c1e606 033485c0e84600 8b45f8 8b00 }
            // n = 5, score = 100
            //   c1f805               | sar                 eax, 5
            //   c1e606               | shl                 esi, 6
            //   033485c0e84600       | add                 esi, dword ptr [eax*4 + 0x46e8c0]
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8b00                 | mov                 eax, dword ptr [eax]

        $sequence_18 = { 99 83ec0c 53 83e203 }
            // n = 4, score = 100
            //   99                   | cdq                 
            //   83ec0c               | sub                 esp, 0xc
            //   53                   | push                ebx
            //   83e203               | and                 edx, 3

        $sequence_19 = { 8a10 88541df8 43 40 8945f4 }
            // n = 5, score = 100
            //   8a10                 | mov                 dl, byte ptr [eax]
            //   88541df8             | mov                 byte ptr [ebp + ebx - 8], dl
            //   43                   | inc                 ebx
            //   40                   | inc                 eax
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax

        $sequence_20 = { e8???????? 83c404 85c0 7510 8a45ff }
            // n = 5, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax
            //   7510                 | jne                 0x12
            //   8a45ff               | mov                 al, byte ptr [ebp - 1]

        $sequence_21 = { e8???????? 83c404 8bf8 395d08 0f845f010000 c745f4c0884000 8b45f4 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8bf8                 | mov                 edi, eax
            //   395d08               | cmp                 dword ptr [ebp + 8], ebx
            //   0f845f010000         | je                  0x165
            //   c745f4c0884000       | mov                 dword ptr [ebp - 0xc], 0x4088c0
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

    condition:
        7 of them and filesize < 1642496
}