rule win_soraya_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.soraya."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.soraya"
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
        $sequence_0 = { ff15???????? 8d48bf 80f919 77f2 }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   8d48bf               | lea                 ecx, dword ptr [eax - 0x41]
            //   80f919               | cmp                 cl, 0x19
            //   77f2                 | ja                  0xfffffff4

        $sequence_1 = { 8a0d???????? 32c1 8a0d???????? 02c8 0fb6c1 0fb64df3 }
            // n = 6, score = 100
            //   8a0d????????         |                     
            //   32c1                 | xor                 al, cl
            //   8a0d????????         |                     
            //   02c8                 | add                 cl, al
            //   0fb6c1               | movzx               eax, cl
            //   0fb64df3             | movzx               ecx, byte ptr [ebp - 0xd]

        $sequence_2 = { e8???????? 488bcf 488bd0 488bd8 ff15???????? 458bc7 33d2 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488bcf               | test                edi, edi
            //   488bd0               | dec                 ecx
            //   488bd8               | lea                 ecx, dword ptr [edx + 0x1e0]
            //   ff15????????         |                     
            //   458bc7               | dec                 eax
            //   33d2                 | mov                 ecx, edi

        $sequence_3 = { 8932 8b552c 8b7dfc 2b7d24 893a c9 }
            // n = 6, score = 100
            //   8932                 | mov                 dword ptr [edx], esi
            //   8b552c               | mov                 edx, dword ptr [ebp + 0x2c]
            //   8b7dfc               | mov                 edi, dword ptr [ebp - 4]
            //   2b7d24               | sub                 edi, dword ptr [ebp + 0x24]
            //   893a                 | mov                 dword ptr [edx], edi
            //   c9                   | leave               

        $sequence_4 = { 8b45f8 33c6 2bc3 50 }
            // n = 4, score = 100
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   33c6                 | xor                 eax, esi
            //   2bc3                 | sub                 eax, ebx
            //   50                   | push                eax

        $sequence_5 = { 7512 0fbdc1 c1d30b 0fbdc1 }
            // n = 4, score = 100
            //   7512                 | jne                 0x14
            //   0fbdc1               | bsr                 eax, ecx
            //   c1d30b               | rcl                 ebx, 0xb
            //   0fbdc1               | bsr                 eax, ecx

        $sequence_6 = { 85c0 0f84a6000000 488d780c e8???????? }
            // n = 4, score = 100
            //   85c0                 | test                eax, eax
            //   0f84a6000000         | je                  0xac
            //   488d780c             | dec                 eax
            //   e8????????           |                     

        $sequence_7 = { 4c8b15???????? 4533f6 85ff 498d8ae0010000 }
            // n = 4, score = 100
            //   4c8b15????????       |                     
            //   4533f6               | lea                 edi, dword ptr [eax + 0xc]
            //   85ff                 | inc                 ebp
            //   498d8ae0010000       | xor                 esi, esi

        $sequence_8 = { c7450871d90500 0fbdc1 8b4508 8b4d0c }
            // n = 4, score = 100
            //   c7450871d90500       | mov                 dword ptr [ebp + 8], 0x5d971
            //   0fbdc1               | bsr                 eax, ecx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]

        $sequence_9 = { 817d1888130000 7372 56 8b35???????? }
            // n = 4, score = 100
            //   817d1888130000       | cmp                 dword ptr [ebp + 0x18], 0x1388
            //   7372                 | jae                 0x74
            //   56                   | push                esi
            //   8b35????????         |                     

        $sequence_10 = { 57 8bd3 e8???????? 59 83f801 }
            // n = 5, score = 100
            // 
            //   8bd3                 | mov                 edx, ebx
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   83f801               | cmp                 eax, 1

        $sequence_11 = { 3bc3 754e 33d2 85c0 7422 4d8bc2 498d4e44 }
            // n = 7, score = 100
            //   3bc3                 | mov                 eax, edi
            //   754e                 | xor                 edx, edx
            //   33d2                 | cmp                 eax, 1
            //   85c0                 | jne                 0x93
            //   7422                 | cmp                 byte ptr [edi], 0x48
            //   4d8bc2               | je                  0x77
            //   498d4e44             | cmp                 byte ptr [edi + 0xb], 0xc3

        $sequence_12 = { 83f801 0f858d000000 803f48 7472 807f0bc3 }
            // n = 5, score = 100
            //   83f801               | dec                 eax
            //   0f858d000000         | mov                 edx, eax
            //   803f48               | dec                 eax
            //   7472                 | mov                 ebx, eax
            //   807f0bc3             | inc                 ebp

        $sequence_13 = { 59 e8???????? 6a0a ff75f8 ff75f0 e8???????? }
            // n = 6, score = 100
            //   59                   | pop                 ecx
            //   e8????????           |                     
            //   6a0a                 | push                0xa
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   e8????????           |                     

        $sequence_14 = { 83f813 0f8389000000 8d3400 0fb70437 }
            // n = 4, score = 100
            //   83f813               | cmp                 eax, 0x13
            //   0f8389000000         | jae                 0x8f
            //   8d3400               | lea                 esi, dword ptr [eax + eax]
            //   0fb70437             | movzx               eax, word ptr [edi + esi]

        $sequence_15 = { 751e 33c9 85ff 740c }
            // n = 4, score = 100
            //   751e                 | cmp                 eax, ebx
            //   33c9                 | jne                 0x5b
            //   85ff                 | xor                 edx, edx
            //   740c                 | test                eax, eax

        $sequence_16 = { 8b45e0 8b55e4 2d6b0f0000 0fafc2 8b55e8 0bc2 }
            // n = 6, score = 100
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]
            //   2d6b0f0000           | sub                 eax, 0xf6b
            //   0fafc2               | imul                eax, edx
            //   8b55e8               | mov                 edx, dword ptr [ebp - 0x18]
            //   0bc2                 | or                  eax, edx

        $sequence_17 = { 83c102 8b7dfc 8bc7 2b4524 }
            // n = 4, score = 100
            //   83c102               | add                 ecx, 2
            //   8b7dfc               | mov                 edi, dword ptr [ebp - 4]
            //   8bc7                 | mov                 eax, edi
            //   2b4524               | sub                 eax, dword ptr [ebp + 0x24]

        $sequence_18 = { 4c8d45d0 448bc8 e8???????? 4885c0 }
            // n = 4, score = 100
            //   4c8d45d0             | je                  0x26
            //   448bc8               | dec                 ebp
            //   e8????????           |                     
            //   4885c0               | mov                 eax, edx

        $sequence_19 = { 72b5 57 56 53 e8???????? 8d041f }
            // n = 6, score = 100
            //   72b5                 | jb                  0xffffffb7
            //   57                   | push                edi
            //   56                   | push                esi
            //   53                   | push                ebx
            //   e8????????           |                     
            //   8d041f               | lea                 eax, dword ptr [edi + ebx]

        $sequence_20 = { 8bc8 8945d4 8b45d0 c1e102 33d6 }
            // n = 5, score = 100
            //   8bc8                 | mov                 ecx, eax
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax
            //   8b45d0               | mov                 eax, dword ptr [ebp - 0x30]
            //   c1e102               | shl                 ecx, 2
            //   33d6                 | xor                 edx, esi

        $sequence_21 = { e8???????? 8bd8 807c1e015e 59 59 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   807c1e015e           | cmp                 byte ptr [esi + ebx + 1], 0x5e
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx

        $sequence_22 = { 8bf0 85f6 740a 56 e8???????? 59 }
            // n = 6, score = 100
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   740a                 | je                  0xc
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx

    condition:
        7 of them and filesize < 188416
}