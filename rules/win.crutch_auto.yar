rule win_crutch_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.crutch."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crutch"
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
        $sequence_0 = { 5e c3 8b442408 56 33f6 3bc6 7462 }
            // n = 7, score = 100
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   8b442408             | mov                 eax, dword ptr [esp + 8]
            //   56                   | push                esi
            //   33f6                 | xor                 esi, esi
            //   3bc6                 | cmp                 eax, esi
            //   7462                 | je                  0x64

        $sequence_1 = { 33c0 33c9 51 50 8d8c2484000000 51 e8???????? }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   33c9                 | xor                 ecx, ecx
            //   51                   | push                ecx
            //   50                   | push                eax
            //   8d8c2484000000       | lea                 ecx, dword ptr [esp + 0x84]
            //   51                   | push                ecx
            //   e8????????           |                     

        $sequence_2 = { 85c0 0f85ef140000 33db 399eac480000 7508 399ec4480000 7416 }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   0f85ef140000         | jne                 0x14f5
            //   33db                 | xor                 ebx, ebx
            //   399eac480000         | cmp                 dword ptr [esi + 0x48ac], ebx
            //   7508                 | jne                 0xa
            //   399ec4480000         | cmp                 dword ptr [esi + 0x48c4], ebx
            //   7416                 | je                  0x18

        $sequence_3 = { 8bf8 83c40c 3bfb 0f8451feffff 5f 5b 5e }
            // n = 7, score = 100
            //   8bf8                 | mov                 edi, eax
            //   83c40c               | add                 esp, 0xc
            //   3bfb                 | cmp                 edi, ebx
            //   0f8451feffff         | je                  0xfffffe57
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx
            //   5e                   | pop                 esi

        $sequence_4 = { 8b4e28 8d542424 52 8b15???????? 50 8b420c 53 }
            // n = 7, score = 100
            //   8b4e28               | mov                 ecx, dword ptr [esi + 0x28]
            //   8d542424             | lea                 edx, dword ptr [esp + 0x24]
            //   52                   | push                edx
            //   8b15????????         |                     
            //   50                   | push                eax
            //   8b420c               | mov                 eax, dword ptr [edx + 0xc]
            //   53                   | push                ebx

        $sequence_5 = { 5b e9???????? 8b742418 85f6 7477 8bca }
            // n = 6, score = 100
            //   5b                   | pop                 ebx
            //   e9????????           |                     
            //   8b742418             | mov                 esi, dword ptr [esp + 0x18]
            //   85f6                 | test                esi, esi
            //   7477                 | je                  0x79
            //   8bca                 | mov                 ecx, edx

        $sequence_6 = { 8a540108 88540444 40 83f810 7cf2 8b4c2414 8d842498020000 }
            // n = 7, score = 100
            //   8a540108             | mov                 dl, byte ptr [ecx + eax + 8]
            //   88540444             | mov                 byte ptr [esp + eax + 0x44], dl
            //   40                   | inc                 eax
            //   83f810               | cmp                 eax, 0x10
            //   7cf2                 | jl                  0xfffffff4
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   8d842498020000       | lea                 eax, dword ptr [esp + 0x298]

        $sequence_7 = { 7412 3bca 0f8f0c0b0000 7c08 3bc3 0f87020b0000 85c9 }
            // n = 7, score = 100
            //   7412                 | je                  0x14
            //   3bca                 | cmp                 ecx, edx
            //   0f8f0c0b0000         | jg                  0xb12
            //   7c08                 | jl                  0xa
            //   3bc3                 | cmp                 eax, ebx
            //   0f87020b0000         | ja                  0xb08
            //   85c9                 | test                ecx, ecx

        $sequence_8 = { 8b37 8b5f08 83ec10 8bc4 8908 8b4c242c 895004 }
            // n = 7, score = 100
            //   8b37                 | mov                 esi, dword ptr [edi]
            //   8b5f08               | mov                 ebx, dword ptr [edi + 8]
            //   83ec10               | sub                 esp, 0x10
            //   8bc4                 | mov                 eax, esp
            //   8908                 | mov                 dword ptr [eax], ecx
            //   8b4c242c             | mov                 ecx, dword ptr [esp + 0x2c]
            //   895004               | mov                 dword ptr [eax + 4], edx

        $sequence_9 = { 3b5624 eb0c 85c0 0f8519010000 837e1400 0f850f010000 8b4310 }
            // n = 7, score = 100
            //   3b5624               | cmp                 edx, dword ptr [esi + 0x24]
            //   eb0c                 | jmp                 0xe
            //   85c0                 | test                eax, eax
            //   0f8519010000         | jne                 0x11f
            //   837e1400             | cmp                 dword ptr [esi + 0x14], 0
            //   0f850f010000         | jne                 0x115
            //   8b4310               | mov                 eax, dword ptr [ebx + 0x10]

    condition:
        7 of them and filesize < 1067008
}