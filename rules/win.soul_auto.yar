rule win_soul_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.soul."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.soul"
        malpedia_rule_date = "20230124"
        malpedia_hash = "2ee0eebba83dce3d019a90519f2f972c0fcf9686"
        malpedia_version = "20230125"
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
        $sequence_0 = { 732f 8b55fc 3b5510 7327 8b55b0 8b5dec }
            // n = 6, score = 400
            //   732f                 | mov                 ecx, dword ptr [ebp - 0x18]
            //   8b55fc               | mov                 dword ptr [ebp - 0x2c], ecx
            //   3b5510               | mov                 ecx, dword ptr [ebp - 0x3c]
            //   7327                 | mov                 dword ptr [ebp - 0x30], edx
            //   8b55b0               | add                 ebx, edi
            //   8b5dec               | mov                 edi, dword ptr [ebp - 0x44]

        $sequence_1 = { c1e90b 0faf4df0 3bf1 7306 }
            // n = 4, score = 400
            //   c1e90b               | mov                 eax, dword ptr [ebp + 8]
            //   0faf4df0             | cmp                 eax, dword ptr [ebp - 4]
            //   3bf1                 | jae                 0x202
            //   7306                 | movzx               ecx, byte ptr [eax]

        $sequence_2 = { d3e2 8515???????? 7405 e8???????? }
            // n = 4, score = 400
            //   d3e2                 | shl                 edx, cl
            //   8515????????         |                     
            //   7405                 | je                  7
            //   e8????????           |                     

        $sequence_3 = { 81c7680a0000 81fa00000001 7318 3b45fc }
            // n = 4, score = 400
            //   81c7680a0000         | mov                 word ptr [edi], bx
            //   81fa00000001         | add                 ecx, ecx
            //   7318                 | not                 edx
            //   3b45fc               | jmp                 0x21

        $sequence_4 = { 03d2 668939 8d7cd104 c745f800000000 c745e408000000 e9???????? 2bc7 }
            // n = 7, score = 400
            //   03d2                 | dec                 eax
            //   668939               | lea                 ecx, [ebp - 0x10]
            //   8d7cd104             | je                  0x5e
            //   c745f800000000       | jne                 0x55
            //   c745e408000000       | dec                 eax
            //   e9????????           |                     
            //   2bc7                 | lea                 ecx, [0x1b354]

        $sequence_5 = { ff25???????? ff25???????? 48895c2408 4889742410 }
            // n = 4, score = 400
            //   ff25????????         |                     
            //   ff25????????         |                     
            //   48895c2408           | dec                 eax
            //   4889742410           | mov                 dword ptr [esp + 8], ebx

        $sequence_6 = { 8b5dec 8b7d08 e9???????? 5f 5e b801000000 5b }
            // n = 7, score = 400
            //   8b5dec               | add                 ecx, edx
            //   8b7d08               | mov                 edx, ecx
            //   e9????????           |                     
            //   5f                   | mov                 ecx, dword ptr [ebp - 8]
            //   5e                   | mov                 word ptr [ecx + edi*2], dx
            //   b801000000           | cmp                 eax, dword ptr [ebp - 4]
            //   5b                   | jae                 0x1ff

        $sequence_7 = { 5d c3 57 eb05 }
            // n = 4, score = 400
            //   5d                   | movzx               ecx, byte ptr [eax]
            //   c3                   | shl                 esi, 8
            //   57                   | mov                 dword ptr [ebp - 0x20], eax
            //   eb05                 | mov                 eax, dword ptr [edi + 0x40]

        $sequence_8 = { b801000000 e9???????? 8b4f24 8b5f38 3bcb 7305 8b4728 }
            // n = 7, score = 400
            //   b801000000           | lea                 edi, [edi + edi + 1]
            //   e9????????           |                     
            //   8b4f24               | cmp                 edi, 0x40
            //   8b5f38               | jb                  0xffffffc1
            //   3bcb                 | sub                 edi, 0x40
            //   7305                 | mov                 dword ptr [ebp + 8], eax
            //   8b4728               | cmp                 edi, 4

        $sequence_9 = { 83c10b 894dec e9???????? 2bc7 2bf7 8bfa }
            // n = 6, score = 400
            //   83c10b               | mov                 edi, eax
            //   894dec               | mov                 dword ptr [ebp - 8], edx
            //   e9????????           |                     
            //   2bc7                 | movzx               edx, word ptr [edx]
            //   2bf7                 | jae                 0xad
            //   8bfa                 | cmp                 dword ptr [ebp - 0x14], 0x13

        $sequence_10 = { e8???????? e9???????? 48c7458007000000 4c89742478 664489742468 33c0 4883c9ff }
            // n = 7, score = 200
            //   e8????????           |                     
            //   e9????????           |                     
            //   48c7458007000000     | cmp                 edx, dword ptr [ebp + 0x10]
            //   4c89742478           | jae                 0x2f
            //   664489742468         | mov                 edx, dword ptr [ebp - 0x50]
            //   33c0                 | mov                 ebx, dword ptr [ebp - 0x14]
            //   4883c9ff             | add                 edi, 0xa68

        $sequence_11 = { 488d4dd0 e8???????? ff15???????? 448bc0 488d153e250200 488d4dd0 ff15???????? }
            // n = 7, score = 200
            //   488d4dd0             | test                ecx, ecx
            //   e8????????           |                     
            //   ff15????????         |                     
            //   448bc0               | dec                 eax
            //   488d153e250200       | mov                 dword ptr [esp + 8], ebx
            //   488d4dd0             | dec                 eax
            //   ff15????????         |                     

        $sequence_12 = { 745c 833d????????01 7553 488d0d54b30100 e8???????? 33ff }
            // n = 6, score = 200
            //   745c                 | sub                 esp, 0x30
            //   833d????????01       |                     
            //   7553                 | dec                 eax
            //   488d0d54b30100       | mov                 ebx, ecx
            //   e8????????           |                     
            //   33ff                 | dec                 eax

        $sequence_13 = { 4533c0 488d55ef 488d4da7 e8???????? }
            // n = 4, score = 200
            //   4533c0               | jae                 0xe
            //   488d55ef             | jae                 0x31
            //   488d4da7             | mov                 edx, dword ptr [ebp - 4]
            //   e8????????           |                     

        $sequence_14 = { 4533c0 488d55c8 488d4df0 e8???????? 488d542448 488d4df0 e8???????? }
            // n = 7, score = 200
            //   4533c0               | mov                 dword ptr [esp + 8], ebx
            //   488d55c8             | dec                 eax
            //   488d4df0             | mov                 dword ptr [esp + 0x10], esi
            //   e8????????           |                     
            //   488d542448           | push                edi
            //   488d4df0             | dec                 eax
            //   e8????????           |                     

        $sequence_15 = { 498bcc e8???????? 85c0 0f84e9000000 488d15ca0f0200 488bcb e8???????? }
            // n = 7, score = 200
            //   498bcc               | dec                 eax
            //   e8????????           |                     
            //   85c0                 | mov                 dword ptr [esp + 8], ebx
            //   0f84e9000000         | dec                 eax
            //   488d15ca0f0200       | mov                 dword ptr [esp + 0x10], esi
            //   488bcb               | push                edi
            //   e8????????           |                     

        $sequence_16 = { 4883ec20 4d8b21 4533ff 4d8bf1 }
            // n = 4, score = 200
            //   4883ec20             | push                edi
            //   4d8b21               | jmp                 9
            //   4533ff               | mov                 dword ptr [ebp - 0x1c], ecx
            //   4d8bf1               | jmp                 0x25

        $sequence_17 = { 66f2af 6689442420 48f7d1 4c8d41ff 488d4c2420 e8???????? 488d4c2420 }
            // n = 7, score = 200
            //   66f2af               | sub                 eax, edi
            //   6689442420           | sub                 esi, edi
            //   48f7d1               | mov                 edi, edx
            //   4c8d41ff             | shr                 edi, 5
            //   488d4c2420           | mov                 edx, dword ptr [ebp - 8]
            //   e8????????           |                     
            //   488d4c2420           | mov                 word ptr [edx], cx

        $sequence_18 = { 03d0 8d0452 488b542418 c1e008 4d8d1442 }
            // n = 5, score = 200
            //   03d0                 | sub                 edx, edi
            //   8d0452               | mov                 word ptr [ecx + 0x646], dx
            //   488b542418           | add                 edi, edx
            //   c1e008               | mov                 word ptr [ecx + 2], di
            //   4d8d1442             | mov                 edx, 2

        $sequence_19 = { ffe1 418b5610 85d2 7509 45895e08 e9???????? 83ff10 }
            // n = 7, score = 200
            //   ffe1                 | mov                 dword ptr [esp + 0x10], esi
            //   418b5610             | push                edi
            //   85d2                 | dec                 eax
            //   7509                 | sub                 esp, 0x30
            //   45895e08             | dec                 eax
            //   e9????????           |                     
            //   83ff10               | mov                 dword ptr [esp + 8], ebx

        $sequence_20 = { e8???????? 4c8d1d111f0100 4c895c2428 488d154d6d0100 488d4c2428 }
            // n = 5, score = 200
            //   e8????????           |                     
            //   4c8d1d111f0100       | jmp                 0x1f
            //   4c895c2428           | shr                 ecx, 0xb
            //   488d154d6d0100       | imul                ecx, dword ptr [ebp - 0x10]
            //   488d4c2428           | cmp                 esi, ecx

        $sequence_21 = { 488d0587fdffff 48894740 488d058cfdffff 48894748 8b442424 4c896770 894768 }
            // n = 7, score = 200
            //   488d0587fdffff       | mov                 ecx, dword ptr [ebp - 0x20]
            //   48894740             | movzx               edx, word ptr [ecx + ebx*2 + 0x180]
            //   488d058cfdffff       | cmp                 eax, 0x1000000
            //   48894748             | sub                 eax, edi
            //   8b442424             | sub                 esi, edi
            //   4c896770             | mov                 edi, edx
            //   894768               | shr                 edi, 5

        $sequence_22 = { 4885c0 746a 4c8bc0 0fb7d3 8bce e8???????? }
            // n = 6, score = 200
            //   4885c0               | dec                 eax
            //   746a                 | sub                 esp, 0x30
            //   4c8bc0               | dec                 eax
            //   0fb7d3               | mov                 ebx, ecx
            //   8bce                 | dec                 eax
            //   e8????????           |                     

    condition:
        7 of them and filesize < 1400832
}