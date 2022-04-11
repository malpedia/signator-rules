rule win_tiger_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.tiger_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tiger_rat"
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
        $sequence_0 = { 41b854000000 8b5108 488b4910 4533c9 }
            // n = 4, score = 200
            //   41b854000000         | mov                 eax, 0x4c
            //   8b5108               | mov                 dword ptr [eax], edi
            //   488b4910             | dec                 eax
            //   4533c9               | mov                 eax, dword ptr [esi + 0x18]

        $sequence_1 = { 0f85c4000000 488d4d34 33d2 41b834040000 c7453038040000 }
            // n = 5, score = 200
            //   0f85c4000000         | mov                 eax, dword ptr [esi + 0x18]
            //   488d4d34             | mov                 dword ptr [eax + 4], 0x33
            //   33d2                 | dec                 eax
            //   41b834040000         | mov                 eax, dword ptr [esi + 0x18]
            //   c7453038040000       | mov                 dword ptr [eax + 8], 0x40

        $sequence_2 = { 4863ca 0fb60c01 41884aff 453bcb }
            // n = 4, score = 200
            //   4863ca               | dec                 eax
            //   0fb60c01             | mov                 eax, dword ptr [esi + 0x18]
            //   41884aff             | inc                 ecx
            //   453bcb               | mov                 eax, 0x53

        $sequence_3 = { 41b841000000 4889442420 e8???????? 4881c4a0000000 }
            // n = 4, score = 200
            //   41b841000000         | mov                 ecx, ebx
            //   4889442420           | xor                 edx, edx
            //   e8????????           |                     
            //   4881c4a0000000       | xor                 ecx, ecx

        $sequence_4 = { 33c0 4c8d0593ffffff 4533c9 4889442428 }
            // n = 4, score = 200
            //   33c0                 | mov                 ecx, eax
            //   4c8d0593ffffff       | xor                 eax, eax
            //   4533c9               | dec                 esp
            //   4889442428           | lea                 eax, dword ptr [0xfffffc03]

        $sequence_5 = { 33c0 4c8d0503fcffff 4889442428 4c8bcb 33d2 }
            // n = 5, score = 200
            //   33c0                 | movzx               eax, byte ptr [ebx]
            //   4c8d0503fcffff       | inc                 ecx
            //   4889442428           | dec                 esi
            //   4c8bcb               | cmp                 al, 0x3d
            //   33d2                 | je                  0x140

        $sequence_6 = { 41b84c000000 8938 488b4618 c7400433000000 }
            // n = 4, score = 200
            //   41b84c000000         | xor                 eax, eax
            //   8938                 | dec                 esp
            //   488b4618             | lea                 eax, dword ptr [0xfffffc03]
            //   c7400433000000       | dec                 eax

        $sequence_7 = { 41b853000000 8b5108 488b4910 48896c2420 }
            // n = 4, score = 200
            //   41b853000000         | dec                 eax
            //   8b5108               | mov                 dword ptr [esp + 0x28], eax
            //   488b4910             | xor                 edx, edx
            //   48896c2420           | xor                 eax, eax

        $sequence_8 = { c3 418bc8 e8???????? 48c743180f000000 }
            // n = 4, score = 100
            //   c3                   | dec                 eax
            //   418bc8               | lea                 edx, dword ptr [esp + 0x80]
            //   e8????????           |                     
            //   48c743180f000000     | inc                 ecx

        $sequence_9 = { 0f1f8000000000 0fb603 41ffce 3c3d 0f8432010000 0fb6c8 }
            // n = 6, score = 100
            //   0f1f8000000000       | inc                 ecx
            //   0fb603               | pop                 edi
            //   41ffce               | pop                 esi
            //   3c3d                 | ret                 
            //   0f8432010000         | mov                 ecx, dword ptr [esi + 0xb0]
            //   0fb6c8               | dec                 esp

        $sequence_10 = { c74424602a420000 c644244000 e8???????? 8b05???????? }
            // n = 4, score = 100
            //   c74424602a420000     | mov                 ecx, dword ptr [esi + 0x30]
            //   c644244000           | mov                 byte ptr [esp + 0x80], 0
            //   e8????????           |                     
            //   8b05????????         |                     

        $sequence_11 = { 448d4228 4903c8 e8???????? 4883675000 83675800 83675c00 488d05f9c5ffff }
            // n = 7, score = 100
            //   448d4228             | mov                 ecx, dword ptr [ebp - 0x29]
            //   4903c8               | dec                 eax
            //   e8????????           |                     
            //   4883675000           | mov                 ecx, dword ptr [ebp - 0x31]
            //   83675800             | dec                 eax
            //   83675c00             | mov                 ebx, dword ptr [esp + 0x120]
            //   488d05f9c5ffff       | inc                 esp

        $sequence_12 = { 488b4dd7 ff15???????? 488b4dcf ff15???????? 488b9c2420010000 }
            // n = 5, score = 100
            //   488b4dd7             | dec                 eax
            //   ff15????????         |                     
            //   488b4dcf             | mov                 ecx, dword ptr [esi + 0xb8]
            //   ff15????????         |                     
            //   488b9c2420010000     | dec                 eax

        $sequence_13 = { 4881c498000000 415f 5e c3 8b8eb0000000 4c8b4e30 }
            // n = 6, score = 100
            //   4881c498000000       | lea                 eax, dword ptr [edx + 0x28]
            //   415f                 | dec                 ecx
            //   5e                   | add                 ecx, eax
            //   c3                   | dec                 eax
            //   8b8eb0000000         | and                 dword ptr [edi + 0x50], 0
            //   4c8b4e30             | and                 dword ptr [edi + 0x58], 0

        $sequence_14 = { 488b8eb8000000 4c8d35ec5d0100 f0ff09 7511 488b8eb8000000 }
            // n = 5, score = 100
            // 
            //   4c8d35ec5d0100       | dec                 esp
            //   f0ff09               | lea                 esi, dword ptr [0x15dec]
            //   7511                 | lock dec            dword ptr [ecx]
            //   488b8eb8000000       | jne                 0x13

        $sequence_15 = { c684248000000000 e8???????? 488d942480000000 41b804010000 33c9 ff15???????? 4533e4 }
            // n = 7, score = 100
            //   c684248000000000     | and                 dword ptr [edi + 0x5c], 0
            //   e8????????           |                     
            //   488d942480000000     | dec                 eax
            //   41b804010000         | lea                 eax, dword ptr [0xffffc5f9]
            //   33c9                 | dec                 eax
            //   ff15????????         |                     
            //   4533e4               | add                 esp, 0x98

    condition:
        7 of them and filesize < 557056
}