rule win_conti_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.conti."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.conti"
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
        $sequence_0 = { f7fb 8856ff 83ef01 75de 5f 5e 5b }
            // n = 7, score = 600
            //   f7fb                 | add                 eax, ecx
            //   8856ff               | add                 eax, eax
            //   83ef01               | cdq                 
            //   75de                 | idiv                esi
            //   5f                   | lea                 eax, [edx + 0x7f]
            //   5e                   | cdq                 
            //   5b                   | mov                 dword ptr [ebp - 4], esi

        $sequence_1 = { 0f1f4000 8a07 8d7f01 0fb6c0 b954000000 2bc8 }
            // n = 6, score = 600
            //   0f1f4000             | pop                 esi
            //   8a07                 | lea                 eax, [eax + eax*8]
            //   8d7f01               | cdq                 
            //   0fb6c0               | idiv                ebx
            //   b954000000           | lea                 eax, [edx + 0x7f]
            //   2bc8                 | cdq                 

        $sequence_2 = { 2bc8 8d0489 c1e002 99 f7ff 8d427f }
            // n = 6, score = 600
            //   2bc8                 | mov                 byte ptr [edi - 1], dl
            //   8d0489               | sub                 ebx, 1
            //   c1e002               | jne                 0xffffffe5
            //   99                   | sub                 ecx, eax
            //   f7ff                 | imul                eax, ecx, 0x2d
            //   8d427f               | cdq                 

        $sequence_3 = { 0fb6c0 2bc8 6bc117 99 f7fb 8d427f 99 }
            // n = 7, score = 600
            //   0fb6c0               | cdq                 
            //   2bc8                 | idiv                esi
            //   6bc117               | mov                 byte ptr [edi - 1], dl
            //   99                   | cdq                 
            //   f7fb                 | idiv                ebx
            //   8d427f               | mov                 byte ptr [esi - 1], dl
            //   99                   | sub                 edi, 1

        $sequence_4 = { 8857ff 83eb01 75da 8b45fc }
            // n = 4, score = 600
            //   8857ff               | sub                 edi, 1
            //   83eb01               | jne                 0xffffffed
            //   75da                 | lea                 eax, [edx + 0x7f]
            //   8b45fc               | cdq                 

        $sequence_5 = { f7fb 8d427f 99 f7fb 8856ff 83ef01 75e1 }
            // n = 7, score = 600
            //   f7fb                 | cdq                 
            //   8d427f               | idiv                edi
            //   99                   | lea                 eax, [edx + 0x7f]
            //   f7fb                 | mov                 ebx, 0xc
            //   8856ff               | push                edi
            //   83ef01               | lea                 edi, [esi + 1]
            //   75e1                 | lea                 esi, [ebx + 0x73]

        $sequence_6 = { 753f 53 bb0c000000 57 8d7e01 8d7373 0f1f4000 }
            // n = 7, score = 600
            //   753f                 | mov                 byte ptr [esi - 1], dl
            //   53                   | sub                 edi, 1
            //   bb0c000000           | jne                 0xffffffe6
            //   57                   | pop                 edi
            //   8d7e01               | pop                 esi
            //   8d7373               | pop                 ebx
            //   0f1f4000             | movzx               eax, al

        $sequence_7 = { 0fb6c0 2bc8 6bc11a 99 }
            // n = 4, score = 600
            //   0fb6c0               | cmp                 byte ptr [esi], 0
            //   2bc8                 | jne                 0x44
            //   6bc11a               | push                ebx
            //   99                   | mov                 ebx, 0xa

        $sequence_8 = { 57 6a04 6800300000 6820005000 }
            // n = 4, score = 400
            //   57                   | push                edi
            //   6a04                 | push                4
            //   6800300000           | push                0x3000
            //   6820005000           | push                0x500020

        $sequence_9 = { 6800100000 68???????? ff75f8 ff15???????? }
            // n = 4, score = 400
            //   6800100000           | push                0x1000
            //   68????????           |                     
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff15????????         |                     

        $sequence_10 = { 6a01 ff15???????? 6aff 8d45fc 50 }
            // n = 5, score = 400
            //   6a01                 | push                1
            //   ff15????????         |                     
            //   6aff                 | push                -1
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax

        $sequence_11 = { 6a00 8d4c2418 51 50 ff742424 }
            // n = 5, score = 400
            //   6a00                 | push                0
            //   8d4c2418             | lea                 ecx, [esp + 0x18]
            //   51                   | push                ecx
            //   50                   | push                eax
            //   ff742424             | push                dword ptr [esp + 0x24]

        $sequence_12 = { 8b4d08 e8???????? 6a00 ff15???????? 33c0 }
            // n = 5, score = 400
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   e8????????           |                     
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax

        $sequence_13 = { 57 e8???????? 85c0 7508 6a01 }
            // n = 5, score = 400
            //   57                   | push                edi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7508                 | jne                 0xa
            //   6a01                 | push                1

        $sequence_14 = { 6a01 6810660000 ff7508 ff15???????? 85c0 }
            // n = 5, score = 400
            //   6a01                 | push                1
            //   6810660000           | push                0x6610
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_15 = { e8???????? 8bb6007d0000 85f6 75ef 6aff 6a01 }
            // n = 6, score = 400
            //   e8????????           |                     
            //   8bb6007d0000         | mov                 esi, dword ptr [esi + 0x7d00]
            //   85f6                 | test                esi, esi
            //   75ef                 | jne                 0xfffffff1
            //   6aff                 | push                -1
            //   6a01                 | push                1

        $sequence_16 = { 4103c3 890424 4133c0 c1c00c 4403f8 448b0424 4503e1 }
            // n = 7, score = 300
            //   4103c3               | inc                 ecx
            //   890424               | add                 eax, ebx
            //   4133c0               | mov                 dword ptr [esp], eax
            //   c1c00c               | inc                 ecx
            //   4403f8               | xor                 eax, eax
            //   448b0424             | rol                 eax, 0xc
            //   4503e1               | inc                 esp

        $sequence_17 = { 448b642420 89442468 4503e2 44336210 418d4501 448b542408 }
            // n = 6, score = 300
            //   448b642420           | add                 edi, eax
            //   89442468             | inc                 esp
            //   4503e2               | mov                 eax, dword ptr [esp]
            //   44336210             | inc                 ebp
            //   418d4501             | add                 esp, ecx
            //   448b542408           | inc                 esp

        $sequence_18 = { 488d7c2424 33d2 90 0fb60417 880411 488d5201 84c0 }
            // n = 7, score = 300
            //   488d7c2424           | movzx               eax, byte ptr [edx + ecx]
            //   33d2                 | mov                 byte ptr [ecx], al
            //   90                   | mov                 ecx, dword ptr [esp + 0x50]
            //   0fb60417             | mov                 eax, 0x2aaaaaab
            //   880411               | add                 ecx, 0xb
            //   488d5201             | imul                ecx
            //   84c0                 | sar                 edx, 2

        $sequence_19 = { 458bc1 482bd0 488d8c24a0000000 0f1f4000 6666660f1f840000000000 0fb6040a 8801 }
            // n = 7, score = 300
            //   458bc1               | lea                 eax, [ebp + 1]
            //   482bd0               | inc                 esp
            //   488d8c24a0000000     | mov                 edx, dword ptr [esp + 8]
            //   0f1f4000             | dec                 eax
            //   6666660f1f840000000000     | test    eax, eax
            //   0fb6040a             | jne                 0x10
            //   8801                 | dec                 eax

        $sequence_20 = { 4885c0 750b 48ffc3 4883fb14 7cd4 eb05 b801000000 }
            // n = 7, score = 300
            //   4885c0               | mov                 esp, dword ptr [esp + 0x20]
            //   750b                 | mov                 dword ptr [esp + 0x68], eax
            //   48ffc3               | inc                 ebp
            //   4883fb14             | add                 esp, edx
            //   7cd4                 | inc                 esp
            //   eb05                 | xor                 esp, dword ptr [edx + 0x10]
            //   b801000000           | inc                 ecx

        $sequence_21 = { 03d0 6bc27f 2bc8 42884c05d8 49ffc0 4983f80c 72af }
            // n = 7, score = 300
            //   03d0                 | mov                 eax, ecx
            //   6bc27f               | dec                 eax
            //   2bc8                 | sub                 edx, eax
            //   42884c05d8           | dec                 eax
            //   49ffc0               | lea                 ecx, [esp + 0xa0]
            //   4983f80c             | nop                 dword ptr [eax]
            //   72af                 | nop                 word ptr [eax + eax]

        $sequence_22 = { 8b4c2450 b8abaaaa2a 83c10b f7e9 c1fa02 8bc2 c1e81f }
            // n = 7, score = 300
            //   8b4c2450             | inc                 ebx
            //   b8abaaaa2a           | dec                 eax
            //   83c10b               | cmp                 ebx, 0x14
            //   f7e9                 | jl                  0xffffffdd
            //   c1fa02               | jmp                 0x10
            //   8bc2                 | mov                 eax, 1
            //   c1e81f               | inc                 ebp

        $sequence_23 = { 488bce ffd0 4885c0 74af 4c897b30 488d4b30 }
            // n = 6, score = 300
            //   488bce               | mov                 eax, edx
            //   ffd0                 | shr                 eax, 0x1f
            //   4885c0               | add                 edx, eax
            //   74af                 | imul                eax, edx, 0x7f
            //   4c897b30             | sub                 ecx, eax
            //   488d4b30             | inc                 edx

    condition:
        7 of them and filesize < 520192
}