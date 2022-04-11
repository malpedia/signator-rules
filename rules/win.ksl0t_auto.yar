rule win_ksl0t_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.ksl0t."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ksl0t"
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
        $sequence_0 = { c68424fa0000003c c68424fb00000038 888424fc000000 888c24fd000000 c68424b000000012 888424b1000000 889c24b2000000 }
            // n = 7, score = 200
            //   c68424fa0000003c     | mov                 byte ptr [esp + 0xfa], 0x3c
            //   c68424fb00000038     | mov                 byte ptr [esp + 0xfb], 0x38
            //   888424fc000000       | mov                 byte ptr [esp + 0xfc], al
            //   888c24fd000000       | mov                 byte ptr [esp + 0xfd], cl
            //   c68424b000000012     | mov                 byte ptr [esp + 0xb0], 0x12
            //   888424b1000000       | mov                 byte ptr [esp + 0xb1], al
            //   889c24b2000000       | mov                 byte ptr [esp + 0xb2], bl

        $sequence_1 = { c68424c30200003b c68424c402000030 c68424c502000039 c68424c602000066 }
            // n = 4, score = 200
            //   c68424c30200003b     | dec                 esp
            //   c68424c402000030     | mov                 dword ptr [eax + 0x48], ebx
            //   c68424c502000039     | dec                 eax
            //   c68424c602000066     | lea                 edx, dword ptr [esp + 0x78]

        $sequence_2 = { 48895c2408 57 4883ec20 488d1d07c80000 488b3b }
            // n = 5, score = 200
            //   48895c2408           | call                dword ptr [esp + 0x418]
            //   57                   | dec                 esp
            //   4883ec20             | mov                 ebx, eax
            //   488d1d07c80000       | dec                 eax
            //   488b3b               | mov                 eax, dword ptr [esp + 0x420]

        $sequence_3 = { 889c24a6000000 c68424a700000013 c68424a80000003c c68424a900000039 888424aa000000 c68424ab00000006 c68424ac0000003c }
            // n = 7, score = 200
            //   889c24a6000000       | mov                 byte ptr [esp + 0xa6], bl
            //   c68424a700000013     | mov                 byte ptr [esp + 0xa7], 0x13
            //   c68424a80000003c     | mov                 byte ptr [esp + 0xa8], 0x3c
            //   c68424a900000039     | mov                 byte ptr [esp + 0xa9], 0x39
            //   888424aa000000       | mov                 byte ptr [esp + 0xaa], al
            //   c68424ab00000006     | mov                 byte ptr [esp + 0xab], 6
            //   c68424ac0000003c     | mov                 byte ptr [esp + 0xac], 0x3c

        $sequence_4 = { 488d942418010000 488b8c24e0010000 ff942418040000 4c8bd8 }
            // n = 4, score = 200
            //   488d942418010000     | dec                 eax
            //   488b8c24e0010000     | mov                 dword ptr [esp + 8], ebx
            //   ff942418040000       | push                edi
            //   4c8bd8               | dec                 eax

        $sequence_5 = { 8d642400 308c0410010000 40 83f80f 72f3 }
            // n = 5, score = 200
            //   8d642400             | lea                 esp, dword ptr [esp]
            //   308c0410010000       | xor                 byte ptr [esp + eax + 0x110], cl
            //   40                   | inc                 eax
            //   83f80f               | cmp                 eax, 0xf
            //   72f3                 | jb                  0xfffffff5

        $sequence_6 = { 488d0db9e30000 ff15???????? e9???????? 488d15e7c00000 }
            // n = 4, score = 200
            //   488d0db9e30000       | sub                 esp, 0x20
            //   ff15????????         |                     
            //   e9????????           |                     
            //   488d15e7c00000       | dec                 eax

        $sequence_7 = { 4c8bc1 4c8d0d429cffff 498bc9 e8???????? 85c0 7422 }
            // n = 6, score = 200
            //   4c8bc1               | dec                 eax
            //   4c8d0d429cffff       | mov                 dword ptr [esi + 0xb8], ebx
            //   498bc9               | dec                 esp
            //   e8????????           |                     
            //   85c0                 | mov                 eax, ecx
            //   7422                 | dec                 esp

        $sequence_8 = { 68???????? 8d85000d0000 50 ff15???????? 8d8d000d0000 51 ff15???????? }
            // n = 7, score = 200
            //   68????????           |                     
            //   8d85000d0000         | lea                 eax, dword ptr [ebp + 0xd00]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d8d000d0000         | lea                 ecx, dword ptr [ebp + 0xd00]
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_9 = { 57 50 8d45f0 64a300000000 8965e8 8b9d14150000 }
            // n = 6, score = 200
            //   57                   | push                edi
            //   50                   | push                eax
            //   8d45f0               | lea                 eax, dword ptr [ebp - 0x10]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8965e8               | mov                 dword ptr [ebp - 0x18], esp
            //   8b9d14150000         | mov                 ebx, dword ptr [ebp + 0x1514]

        $sequence_10 = { ff15???????? 83bc24b014000000 752c ff15???????? 898424b4140000 }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   83bc24b014000000     | mov                 byte ptr [esp + 0x2c4], 0x30
            //   752c                 | mov                 byte ptr [esp + 0x2c5], 0x39
            //   ff15????????         |                     
            //   898424b4140000       | mov                 byte ptr [esp + 0x2c6], 0x66

        $sequence_11 = { 740e e8???????? eb07 4c8d25c3720000 48899eb8000000 }
            // n = 5, score = 200
            //   740e                 | je                  0x10
            //   e8????????           |                     
            //   eb07                 | jmp                 9
            //   4c8d25c3720000       | dec                 esp
            //   48899eb8000000       | lea                 esp, dword ptr [0x72c3]

        $sequence_12 = { ff942418040000 4c8bd8 488b842420040000 4c895848 488d542478 }
            // n = 5, score = 200
            //   ff942418040000       | lea                 ecx, dword ptr [0xffff9c42]
            //   4c8bd8               | dec                 ecx
            //   488b842420040000     | mov                 ecx, ecx
            //   4c895848             | test                eax, eax
            //   488d542478           | je                  0x24

        $sequence_13 = { 59 5f 5e 5b 8b8d68080000 }
            // n = 5, score = 200
            //   59                   | pop                 ecx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   8b8d68080000         | mov                 ecx, dword ptr [ebp + 0x868]

        $sequence_14 = { b93b000000 b8???????? 2bc1 8944241c b8???????? 2bc1 }
            // n = 6, score = 200
            //   b93b000000           | mov                 ecx, 0x3b
            //   b8????????           |                     
            //   2bc1                 | sub                 eax, ecx
            //   8944241c             | mov                 dword ptr [esp + 0x1c], eax
            //   b8????????           |                     
            //   2bc1                 | sub                 eax, ecx

        $sequence_15 = { c68424c802000022 c68424c902000001 c68424ca0200003d c68424cb02000027 }
            // n = 4, score = 200
            //   c68424c802000022     | mov                 byte ptr [esp + 0x2c8], 0x22
            //   c68424c902000001     | mov                 byte ptr [esp + 0x2c9], 1
            //   c68424ca0200003d     | mov                 byte ptr [esp + 0x2ca], 0x3d
            //   c68424cb02000027     | mov                 byte ptr [esp + 0x2cb], 0x27

    condition:
        7 of them and filesize < 196608
}