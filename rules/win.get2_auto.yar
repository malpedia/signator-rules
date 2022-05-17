rule win_get2_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.get2."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.get2"
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
        $sequence_0 = { 8d4c2404 742b e8???????? 8d4c240c ff7004 ff30 68???????? }
            // n = 7, score = 1000
            //   8d4c2404             | lea                 ecx, [esp + 4]
            //   742b                 | je                  0x2d
            //   e8????????           |                     
            //   8d4c240c             | lea                 ecx, [esp + 0xc]
            //   ff7004               | push                dword ptr [eax + 4]
            //   ff30                 | push                dword ptr [eax]
            //   68????????           |                     

        $sequence_1 = { 7444 8b4508 660f6ec1 f30fe6c0 c1e91f 51 }
            // n = 6, score = 1000
            //   7444                 | je                  0x46
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   660f6ec1             | movd                xmm0, ecx
            //   f30fe6c0             | cvtdq2pd            xmm0, xmm0
            //   c1e91f               | shr                 ecx, 0x1f
            //   51                   | push                ecx

        $sequence_2 = { 51 52 8d8d24ffffff 895dfc e8???????? }
            // n = 5, score = 1000
            //   51                   | push                ecx
            //   52                   | push                edx
            //   8d8d24ffffff         | lea                 ecx, [ebp - 0xdc]
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   e8????????           |                     

        $sequence_3 = { 50 e8???????? 8b4508 8be5 5d c20400 68d0000000 }
            // n = 7, score = 1000
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   68d0000000           | push                0xd0

        $sequence_4 = { 8b9188000000 32c0 85d2 744e 8b898c000000 85c9 }
            // n = 6, score = 1000
            //   8b9188000000         | mov                 edx, dword ptr [ecx + 0x88]
            //   32c0                 | xor                 al, al
            //   85d2                 | test                edx, edx
            //   744e                 | je                  0x50
            //   8b898c000000         | mov                 ecx, dword ptr [ecx + 0x8c]
            //   85c9                 | test                ecx, ecx

        $sequence_5 = { 897de8 33c0 895dd4 668945d8 51 51 }
            // n = 6, score = 1000
            //   897de8               | mov                 dword ptr [ebp - 0x18], edi
            //   33c0                 | xor                 eax, eax
            //   895dd4               | mov                 dword ptr [ebp - 0x2c], ebx
            //   668945d8             | mov                 word ptr [ebp - 0x28], ax
            //   51                   | push                ecx
            //   51                   | push                ecx

        $sequence_6 = { c20400 68d0000000 b8???????? e8???????? 8bf1 }
            // n = 5, score = 1000
            //   c20400               | ret                 4
            //   68d0000000           | push                0xd0
            //   b8????????           |                     
            //   e8????????           |                     
            //   8bf1                 | mov                 esi, ecx

        $sequence_7 = { 8d44240c 68???????? eb9e 8be5 5d }
            // n = 5, score = 1000
            //   8d44240c             | lea                 eax, [esp + 0xc]
            //   68????????           |                     
            //   eb9e                 | jmp                 0xffffffa0
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp

        $sequence_8 = { 89542420 4c8d0d2146feff 4c8b4570 8b5568 488b4d60 }
            // n = 5, score = 100
            //   89542420             | dec                 eax
            //   4c8d0d2146feff       | lea                 edx, [esp + 0x350]
            //   4c8b4570             | dec                 eax
            //   8b5568               | lea                 ecx, [esp + 0x4b0]
            //   488b4d60             | mov                 dword ptr [esp + 0x70], ecx

        $sequence_9 = { c78424b001000014010000 488d8c24b0010000 ff15???????? 41b804000000 488d15f5700300 }
            // n = 5, score = 100
            //   c78424b001000014010000     | cmp    dword ptr [esi + 0x130], 0
            //   488d8c24b0010000     | mov                 dword ptr [esp + 0x20], edx
            //   ff15????????         |                     
            //   41b804000000         | dec                 esp
            //   488d15f5700300       | lea                 ecx, [0xfffe4621]

        $sequence_10 = { 0fb606 3c20 7510 4885ff }
            // n = 4, score = 100
            //   0fb606               | lea                 eax, [0x2a574]
            //   3c20                 | dec                 eax
            //   7510                 | mov                 dword ptr [ecx], eax
            //   4885ff               | dec                 eax

        $sequence_11 = { 4933d0 4b8794f7c0570400 eb2d 4c8b15???????? }
            // n = 4, score = 100
            //   4933d0               | cmp                 eax, 3
            //   4b8794f7c0570400     | jae                 0xe08
            //   eb2d                 | dec                 ecx
            //   4c8b15????????       |                     

        $sequence_12 = { 4883ec20 488bda 488d0574a50200 488901 488d5108 }
            // n = 5, score = 100
            //   4883ec20             | dec                 eax
            //   488bda               | sub                 esp, 0x20
            //   488d0574a50200       | dec                 eax
            //   488901               | mov                 ebx, edx
            //   488d5108             | dec                 eax

        $sequence_13 = { 894c2470 83f803 0f83ff0d0000 4983be3001000000 }
            // n = 4, score = 100
            //   894c2470             | dec                 eax
            //   83f803               | test                edi, edi
            //   0f83ff0d0000         | test                eax, eax
            //   4983be3001000000     | je                  0x48

        $sequence_14 = { c70301000000 83c8ff e9???????? 488b4b10 }
            // n = 4, score = 100
            //   c70301000000         | dec                 esp
            //   83c8ff               | mov                 eax, dword ptr [ebp + 0x70]
            //   e9????????           |                     
            //   488b4b10             | mov                 edx, dword ptr [ebp + 0x68]

        $sequence_15 = { ff15???????? 85c0 7446 488d942450030000 488d8c24b0040000 }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   85c0                 | lea                 edx, [ecx + 8]
            //   7446                 | movzx               eax, byte ptr [esi]
            //   488d942450030000     | cmp                 al, 0x20
            //   488d8c24b0040000     | jne                 0x14

    condition:
        7 of them and filesize < 720896
}