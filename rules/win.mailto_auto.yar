rule win_mailto_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.mailto."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mailto"
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
        $sequence_0 = { 8b4b40 8a0407 88040b ff4340 837b4040 0f85a0010000 33f6 }
            // n = 7, score = 400
            //   8b4b40               | mov                 ecx, dword ptr [ebx + 0x40]
            //   8a0407               | mov                 al, byte ptr [edi + eax]
            //   88040b               | mov                 byte ptr [ebx + ecx], al
            //   ff4340               | inc                 dword ptr [ebx + 0x40]
            //   837b4040             | cmp                 dword ptr [ebx + 0x40], 0x40
            //   0f85a0010000         | jne                 0x1a6
            //   33f6                 | xor                 esi, esi

        $sequence_1 = { 53 e8???????? 83c404 5d 5b 8bc6 5e }
            // n = 7, score = 400
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi

        $sequence_2 = { 83c004 660f1f440000 3930 740a 41 83c008 3bca }
            // n = 7, score = 400
            //   83c004               | add                 eax, 4
            //   660f1f440000         | nop                 word ptr [eax + eax]
            //   3930                 | cmp                 dword ptr [eax], esi
            //   740a                 | je                  0xc
            //   41                   | inc                 ecx
            //   83c008               | add                 eax, 8
            //   3bca                 | cmp                 ecx, edx

        $sequence_3 = { 8bf2 8bf8 56 57 51 ff742420 e8???????? }
            // n = 7, score = 400
            //   8bf2                 | mov                 esi, edx
            //   8bf8                 | mov                 edi, eax
            //   56                   | push                esi
            //   57                   | push                edi
            //   51                   | push                ecx
            //   ff742420             | push                dword ptr [esp + 0x20]
            //   e8????????           |                     

        $sequence_4 = { 8d842480000000 3bc3 7213 0f1f4000 8b048b 01448c44 41 }
            // n = 7, score = 400
            //   8d842480000000       | lea                 eax, [esp + 0x80]
            //   3bc3                 | cmp                 eax, ebx
            //   7213                 | jb                  0x15
            //   0f1f4000             | nop                 dword ptr [eax]
            //   8b048b               | mov                 eax, dword ptr [ebx + ecx*4]
            //   01448c44             | add                 dword ptr [esp + ecx*4 + 0x44], eax
            //   41                   | inc                 ecx

        $sequence_5 = { 8d4e1f 83c404 8d471f 3bf9 7724 3bc6 }
            // n = 6, score = 400
            //   8d4e1f               | lea                 ecx, [esi + 0x1f]
            //   83c404               | add                 esp, 4
            //   8d471f               | lea                 eax, [edi + 0x1f]
            //   3bf9                 | cmp                 edi, ecx
            //   7724                 | ja                  0x26
            //   3bc6                 | cmp                 eax, esi

        $sequence_6 = { 660fefc8 0f108414b4000000 0f110c17 0f104c28c0 660fefc8 }
            // n = 5, score = 400
            //   660fefc8             | pxor                xmm1, xmm0
            //   0f108414b4000000     | movups              xmm0, xmmword ptr [esp + edx + 0xb4]
            //   0f110c17             | movups              xmmword ptr [edi + edx], xmm1
            //   0f104c28c0           | movups              xmm1, xmmword ptr [eax + ebp - 0x40]
            //   660fefc8             | pxor                xmm1, xmm0

        $sequence_7 = { c744243c61006400 c74424402e006500 c744244478006500 6689442448 e8???????? 8bd8 83c404 }
            // n = 7, score = 400
            //   c744243c61006400     | mov                 dword ptr [esp + 0x3c], 0x640061
            //   c74424402e006500     | mov                 dword ptr [esp + 0x40], 0x65002e
            //   c744244478006500     | mov                 dword ptr [esp + 0x44], 0x650078
            //   6689442448           | mov                 word ptr [esp + 0x48], ax
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   83c404               | add                 esp, 4

        $sequence_8 = { 85f6 745f 681b040a7a 56 e8???????? 8b0d???????? 6850b21d58 }
            // n = 7, score = 400
            //   85f6                 | test                esi, esi
            //   745f                 | je                  0x61
            //   681b040a7a           | push                0x7a0a041b
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b0d????????         |                     
            //   6850b21d58           | push                0x581db250

        $sequence_9 = { 8d8424b0000000 50 e8???????? 56 8d8424b8000000 50 }
            // n = 6, score = 400
            //   8d8424b0000000       | lea                 eax, [esp + 0xb0]
            //   50                   | push                eax
            //   e8????????           |                     
            //   56                   | push                esi
            //   8d8424b8000000       | lea                 eax, [esp + 0xb8]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 180224
}