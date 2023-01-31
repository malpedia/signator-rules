rule win_unidentified_101_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.unidentified_101."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_101"
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
        $sequence_0 = { 4883ec20 488bd9 488bc2 488d0de1600100 0f57c0 48890b 488d5308 }
            // n = 7, score = 100
            //   4883ec20             | and                 ecx, 0xf
            //   488bd9               | dec                 esp
            //   488bc2               | mov                 ecx, dword ptr [esp + 0x68]
            //   488d0de1600100       | dec                 esp
            //   0f57c0               | mov                 eax, dword ptr [esp + 0x58]
            //   48890b               | dec                 eax
            //   488d5308             | mov                 edx, eax

        $sequence_1 = { c68424970200006c c684249802000065 c684249902000048 c684249a02000061 c684249b0200006e c684249c02000064 }
            // n = 6, score = 100
            //   c68424970200006c     | cmp                 dword ptr [esp + 0x40], eax
            //   c684249802000065     | jae                 0xa6b
            //   c684249902000048     | mov                 eax, dword ptr [esp + 0x44]
            //   c684249a02000061     | cmp                 dword ptr [esp + 0x48], eax
            //   c684249b0200006e     | jae                 0x9e3
            //   c684249c02000064     | mov                 eax, dword ptr [esp + 0x48]

        $sequence_2 = { 83e10f 480fbe841100e40100 8a8c1110e40100 4c2bc0 418b40fc d3e8 }
            // n = 6, score = 100
            //   83e10f               | dec                 eax
            //   480fbe841100e40100     | add    esp, 0x20
            //   8a8c1110e40100       | dec                 eax
            //   4c2bc0               | lea                 edx, [0xb3c7]
            //   418b40fc             | mov                 ecx, 0x16
            //   d3e8                 | dec                 esp

        $sequence_3 = { 488b4c2470 ff15???????? 89442444 8b442444 8bc8 e8???????? 4889442468 }
            // n = 7, score = 100
            //   488b4c2470           | dec                 esp
            //   ff15????????         |                     
            //   89442444             | lea                 ecx, [0xd38f]
            //   8b442444             | xor                 edx, 1
            //   8bc8                 | add                 edx, edx
            //   e8????????           |                     
            //   4889442468           | mov                 eax, edx

        $sequence_4 = { 6689442440 b876000000 6689442442 b82e000000 6689442444 b865000000 }
            // n = 6, score = 100
            //   6689442440           | mov                 dword ptr [esp + 0x48], eax
            //   b876000000           | mov                 dword ptr [esp + 0x44], 0
            //   6689442442           | jmp                 0x134b
            //   b82e000000           | mov                 eax, dword ptr [esp + 0x44]
            //   6689442444           | inc                 eax
            //   b865000000           | dec                 eax

        $sequence_5 = { 4189401c 0fb60a 83e10f 4a0fbe840900e40100 428a8c0910e40100 482bd0 8b42fc }
            // n = 7, score = 100
            //   4189401c             | mov                 byte ptr [esp + 0x3c5], 0
            //   0fb60a               | mov                 byte ptr [esp + 0x368], 0x53
            //   83e10f               | mov                 byte ptr [esp + 0x369], 0x65
            //   4a0fbe840900e40100     | mov    byte ptr [esp + 0x1c3], 0x70
            //   428a8c0910e40100     | mov                 byte ptr [esp + 0x1c4], 0x51
            //   482bd0               | mov                 byte ptr [esp + 0x1c5], 0x75
            //   8b42fc               | mov                 byte ptr [esp + 0x1c6], 0x65

        $sequence_6 = { 488d0d8c540100 48890d???????? 488d053e510100 488d0d67530100 }
            // n = 4, score = 100
            //   488d0d8c540100       | mov                 ecx, dword ptr [esp + 0x48]
            //   48890d????????       |                     
            //   488d053e510100       | dec                 eax
            //   488d0d67530100       | mov                 ecx, dword ptr [esp + 0x78]

        $sequence_7 = { e8???????? 84c0 744f e8???????? e8???????? e8???????? 488d153e5b0100 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   84c0                 | imul                eax, eax, 0xc
            //   744f                 | jg                  0x17b
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   488d153e5b0100       | mov                 eax, dword ptr [esp]

        $sequence_8 = { 7505 e8???????? 488b442460 48ffc0 4889442470 488b542470 488b8c2490000000 }
            // n = 7, score = 100
            //   7505                 | dec                 esp
            //   e8????????           |                     
            //   488b442460           | mov                 eax, dword ptr [esp + 0x20]
            //   48ffc0               | inc                 ecx
            //   4889442470           | movzx               eax, byte ptr [eax + eax]
            //   488b542470           | mov                 byte ptr [edx + ecx], al
            //   488b8c2490000000     | dec                 eax

        $sequence_9 = { 668944246a b873000000 668944246c b86f000000 668944246e b866000000 6689442470 }
            // n = 7, score = 100
            //   668944246a           | mov                 ecx, 0x18
            //   b873000000           | rep stosb           byte ptr es:[edi], al
            //   668944246c           | dec                 eax
            //   b86f000000           | mov                 ecx, dword ptr [esp + 0x300]
            //   668944246e           | dec                 eax
            //   b866000000           | mov                 dword ptr [esp + 0x98], eax
            //   6689442470           | dec                 eax

    condition:
        7 of them and filesize < 402432
}