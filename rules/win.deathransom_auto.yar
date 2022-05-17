rule win_deathransom_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.deathransom."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.deathransom"
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
        $sequence_0 = { 897de0 8d040f c1c80e 33c2 8b55dc 8945e4 }
            // n = 6, score = 100
            //   897de0               | mov                 dword ptr [ebp - 0x20], edi
            //   8d040f               | lea                 eax, [edi + ecx]
            //   c1c80e               | ror                 eax, 0xe
            //   33c2                 | xor                 eax, edx
            //   8b55dc               | mov                 edx, dword ptr [ebp - 0x24]
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax

        $sequence_1 = { 237dfc 03fa 8975f8 3bfa 8b55f4 1bc0 23ca }
            // n = 7, score = 100
            //   237dfc               | and                 edi, dword ptr [ebp - 4]
            //   03fa                 | add                 edi, edx
            //   8975f8               | mov                 dword ptr [ebp - 8], esi
            //   3bfa                 | cmp                 edi, edx
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   1bc0                 | sbb                 eax, eax
            //   23ca                 | and                 ecx, edx

        $sequence_2 = { 0f1102 e8???????? 8d464c 85c0 7414 80400301 750e }
            // n = 7, score = 100
            //   0f1102               | movups              xmmword ptr [edx], xmm0
            //   e8????????           |                     
            //   8d464c               | lea                 eax, [esi + 0x4c]
            //   85c0                 | test                eax, eax
            //   7414                 | je                  0x16
            //   80400301             | add                 byte ptr [eax + 3], 1
            //   750e                 | jne                 0x10

        $sequence_3 = { 3bd6 57 0f4ff2 8bf9 8d04b500000000 50 ff7708 }
            // n = 7, score = 100
            //   3bd6                 | cmp                 edx, esi
            //   57                   | push                edi
            //   0f4ff2               | cmovg               esi, edx
            //   8bf9                 | mov                 edi, ecx
            //   8d04b500000000       | lea                 eax, [esi*4]
            //   50                   | push                eax
            //   ff7708               | push                dword ptr [edi + 8]

        $sequence_4 = { 8b75e4 03d1 8bc3 0355fc 8bcb }
            // n = 5, score = 100
            //   8b75e4               | mov                 esi, dword ptr [ebp - 0x1c]
            //   03d1                 | add                 edx, ecx
            //   8bc3                 | mov                 eax, ebx
            //   0355fc               | add                 edx, dword ptr [ebp - 4]
            //   8bcb                 | mov                 ecx, ebx

        $sequence_5 = { 33c6 03ca 2345e4 8b55f0 33c3 03c1 81c2852c7292 }
            // n = 7, score = 100
            //   33c6                 | xor                 eax, esi
            //   03ca                 | add                 ecx, edx
            //   2345e4               | and                 eax, dword ptr [ebp - 0x1c]
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   33c3                 | xor                 eax, ebx
            //   03c1                 | add                 eax, ecx
            //   81c2852c7292         | add                 edx, 0x92722c85

        $sequence_6 = { 8bca e8???????? 8b4d0c 8bd0 33c0 }
            // n = 5, score = 100
            //   8bca                 | mov                 ecx, edx
            //   e8????????           |                     
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8bd0                 | mov                 edx, eax
            //   33c0                 | xor                 eax, eax

        $sequence_7 = { 215df8 0945f8 014df8 8b7de0 8bcf c1c90b }
            // n = 6, score = 100
            //   215df8               | and                 dword ptr [ebp - 8], ebx
            //   0945f8               | or                  dword ptr [ebp - 8], eax
            //   014df8               | add                 dword ptr [ebp - 8], ecx
            //   8b7de0               | mov                 edi, dword ptr [ebp - 0x20]
            //   8bcf                 | mov                 ecx, edi
            //   c1c90b               | ror                 ecx, 0xb

        $sequence_8 = { 33c8 895d98 8bc2 c1c806 33c8 8b45f8 }
            // n = 6, score = 100
            //   33c8                 | xor                 ecx, eax
            //   895d98               | mov                 dword ptr [ebp - 0x68], ebx
            //   8bc2                 | mov                 eax, edx
            //   c1c806               | ror                 eax, 6
            //   33c8                 | xor                 ecx, eax
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

        $sequence_9 = { 85f6 7e19 8d46ff 8d0487 660f1f440000 833800 7508 }
            // n = 7, score = 100
            //   85f6                 | test                esi, esi
            //   7e19                 | jle                 0x1b
            //   8d46ff               | lea                 eax, [esi - 1]
            //   8d0487               | lea                 eax, [edi + eax*4]
            //   660f1f440000         | nop                 word ptr [eax + eax]
            //   833800               | cmp                 dword ptr [eax], 0
            //   7508                 | jne                 0xa

    condition:
        7 of them and filesize < 133120
}