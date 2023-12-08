rule win_conti_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.conti."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.conti"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
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
        $sequence_0 = { 56 57 bf0e000000 8d7101 }
            // n = 4, score = 600
            //   56                   | push                esi
            //   57                   | push                edi
            //   bf0e000000           | mov                 edi, 0xe
            //   8d7101               | lea                 esi, [ecx + 1]

        $sequence_1 = { 8d7f01 0fb6c0 b978000000 2bc8 }
            // n = 4, score = 600
            //   8d7f01               | lea                 edi, [edi + 1]
            //   0fb6c0               | movzx               eax, al
            //   b978000000           | mov                 ecx, 0x78
            //   2bc8                 | sub                 ecx, eax

        $sequence_2 = { 57 bf0a000000 8d7101 8d5f75 8a06 8d7601 0fb6c0 }
            // n = 7, score = 600
            //   57                   | push                edi
            //   bf0a000000           | mov                 edi, 0xa
            //   8d7101               | lea                 esi, [ecx + 1]
            //   8d5f75               | lea                 ebx, [edi + 0x75]
            //   8a06                 | mov                 al, byte ptr [esi]
            //   8d7601               | lea                 esi, [esi + 1]
            //   0fb6c0               | movzx               eax, al

        $sequence_3 = { 8d7f01 0fb6c0 b96c000000 2bc8 }
            // n = 4, score = 600
            //   8d7f01               | lea                 edi, [edi + 1]
            //   0fb6c0               | movzx               eax, al
            //   b96c000000           | mov                 ecx, 0x6c
            //   2bc8                 | sub                 ecx, eax

        $sequence_4 = { 0f1f4000 8a07 8d7f01 0fb6c0 b948000000 }
            // n = 5, score = 600
            //   0f1f4000             | nop                 dword ptr [eax]
            //   8a07                 | mov                 al, byte ptr [edi]
            //   8d7f01               | lea                 edi, [edi + 1]
            //   0fb6c0               | movzx               eax, al
            //   b948000000           | mov                 ecx, 0x48

        $sequence_5 = { 8975fc 803e00 7541 53 bb0a000000 }
            // n = 5, score = 600
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   803e00               | cmp                 byte ptr [esi], 0
            //   7541                 | jne                 0x43
            //   53                   | push                ebx
            //   bb0a000000           | mov                 ebx, 0xa

        $sequence_6 = { 8975fc 803e00 7542 53 bb0e000000 }
            // n = 5, score = 600
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   803e00               | cmp                 byte ptr [esi], 0
            //   7542                 | jne                 0x44
            //   53                   | push                ebx
            //   bb0e000000           | mov                 ebx, 0xe

        $sequence_7 = { 8d7f01 0fb6c0 b909000000 2bc8 }
            // n = 4, score = 600
            //   8d7f01               | lea                 edi, [edi + 1]
            //   0fb6c0               | movzx               eax, al
            //   b909000000           | mov                 ecx, 9
            //   2bc8                 | sub                 ecx, eax

        $sequence_8 = { e8???????? 8bb6007d0000 85f6 75ef 6aff }
            // n = 5, score = 400
            //   e8????????           |                     
            //   8bb6007d0000         | mov                 esi, dword ptr [esi + 0x7d00]
            //   85f6                 | test                esi, esi
            //   75ef                 | jne                 0xfffffff1
            //   6aff                 | push                -1

        $sequence_9 = { 50 6a20 ff15???????? 68???????? ff15???????? 68???????? }
            // n = 6, score = 400
            //   50                   | push                eax
            //   6a20                 | push                0x20
            //   ff15????????         |                     
            //   68????????           |                     
            //   ff15????????         |                     
            //   68????????           |                     

        $sequence_10 = { 780e 7f07 3d00005000 7605 }
            // n = 4, score = 400
            //   780e                 | js                  0x10
            //   7f07                 | jg                  9
            //   3d00005000           | cmp                 eax, 0x500000
            //   7605                 | jbe                 7

        $sequence_11 = { 8bec 8b4d08 e8???????? 6a00 ff15???????? }
            // n = 5, score = 400
            //   8bec                 | mov                 ebp, esp
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   e8????????           |                     
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_12 = { 50 8b4508 ff7004 ff15???????? 85c0 7508 6a01 }
            // n = 7, score = 400
            //   50                   | push                eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   ff7004               | push                dword ptr [eax + 4]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7508                 | jne                 0xa
            //   6a01                 | push                1

        $sequence_13 = { 6810660000 ff7508 ff15???????? 85c0 }
            // n = 4, score = 400
            //   6810660000           | push                0x6610
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_14 = { 85ff 7408 57 56 ff15???????? ff75f8 56 }
            // n = 7, score = 400
            //   85ff                 | test                edi, edi
            //   7408                 | je                  0xa
            //   57                   | push                edi
            //   56                   | push                esi
            //   ff15????????         |                     
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   56                   | push                esi

        $sequence_15 = { 7411 a801 740d 83f001 50 ff7608 }
            // n = 6, score = 400
            //   7411                 | je                  0x13
            //   a801                 | test                al, 1
            //   740d                 | je                  0xf
            //   83f001               | xor                 eax, 1
            //   50                   | push                eax
            //   ff7608               | push                dword ptr [esi + 8]

        $sequence_16 = { 48894c2430 4c8d45ff 488d4d0f 418bd6 48894c2428 488d4d07 48894c2420 }
            // n = 7, score = 300
            //   48894c2430           | dec                 eax
            //   4c8d45ff             | mov                 dword ptr [esp + 0x30], ecx
            //   488d4d0f             | dec                 esp
            //   418bd6               | lea                 eax, [ebp - 1]
            //   48894c2428           | dec                 eax
            //   488d4d07             | lea                 ecx, [ebp + 0xf]
            //   48894c2420           | inc                 ecx

        $sequence_17 = { 42884c0500 49ffc0 4983f80d 72af 44884d0f }
            // n = 5, score = 300
            //   42884c0500           | xor                 eax, eax
            //   49ffc0               | dec                 eax
            //   4983f80d             | mov                 dword ptr [esp + 0x40], ecx
            //   72af                 | dec                 eax
            //   44884d0f             | mov                 dword ptr [esp + 0x48], ecx

        $sequence_18 = { 33d2 ffd0 897c2450 b856555555 }
            // n = 4, score = 300
            //   33d2                 | dec                 eax
            //   ffd0                 | mov                 dword ptr [esp + 0x48], ecx
            //   897c2450             | dec                 eax
            //   b856555555           | lea                 edx, [ebp - 0x20]

        $sequence_19 = { 0fb64500 0fb645ff 84c0 755c }
            // n = 4, score = 300
            //   0fb64500             | xor                 eax, eax
            //   0fb645ff             | dec                 eax
            //   84c0                 | mov                 dword ptr [esp + 0x40], ecx
            //   755c                 | xor                 ecx, ecx

        $sequence_20 = { 488b4f30 488b4738 4885c9 7406 }
            // n = 4, score = 300
            //   488b4f30             | dec                 eax
            //   488b4738             | lea                 ecx, [esp + 0x70]
            //   4885c9               | inc                 ebp
            //   7406                 | xor                 eax, eax

        $sequence_21 = { 48894c2448 488d55e0 488d4c2470 4533c0 }
            // n = 4, score = 300
            //   48894c2448           | mov                 edx, esi
            //   488d55e0             | dec                 eax
            //   488d4c2470           | mov                 dword ptr [esp + 0x28], ecx
            //   4533c0               | dec                 eax

        $sequence_22 = { 42884c0501 49ffc0 4983f80c 72af }
            // n = 4, score = 300
            //   42884c0501           | test                ecx, ecx
            //   49ffc0               | je                  0x13
            //   4983f80c             | dec                 eax
            //   72af                 | mov                 ecx, dword ptr [edi + 0x30]

        $sequence_23 = { 41b801000000 488bd3 8bcf ffd0 4d85f6 }
            // n = 5, score = 300
            //   41b801000000         | dec                 eax
            //   488bd3               | lea                 edx, [ebp - 0x20]
            //   8bcf                 | dec                 eax
            //   ffd0                 | lea                 ecx, [esp + 0x70]
            //   4d85f6               | inc                 ebp

    condition:
        7 of them and filesize < 520192
}