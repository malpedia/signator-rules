rule win_bee_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.bee."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bee"
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
        $sequence_0 = { 56 be05000000 bb01000000 3974240c }
            // n = 4, score = 100
            //   56                   | push                esi
            //   be05000000           | mov                 esi, 5
            //   bb01000000           | mov                 ebx, 1
            //   3974240c             | cmp                 dword ptr [esp + 0xc], esi

        $sequence_1 = { 895c2428 e8???????? 83c410 83f804 7445 56 e8???????? }
            // n = 7, score = 100
            //   895c2428             | mov                 dword ptr [esp + 0x28], ebx
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   83f804               | cmp                 eax, 4
            //   7445                 | je                  0x47
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_2 = { 8b4c2424 803c3900 7408 81fd00000100 7c86 }
            // n = 5, score = 100
            //   8b4c2424             | mov                 ecx, dword ptr [esp + 0x24]
            //   803c3900             | cmp                 byte ptr [ecx + edi], 0
            //   7408                 | je                  0xa
            //   81fd00000100         | cmp                 ebp, 0x10000
            //   7c86                 | jl                  0xffffff88

        $sequence_3 = { 8b13 8b02 6a01 8bcb ffd0 e9???????? 8b00 }
            // n = 7, score = 100
            //   8b13                 | mov                 edx, dword ptr [ebx]
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   6a01                 | push                1
            //   8bcb                 | mov                 ecx, ebx
            //   ffd0                 | call                eax
            //   e9????????           |                     
            //   8b00                 | mov                 eax, dword ptr [eax]

        $sequence_4 = { 51 e8???????? 8b542464 83c404 52 }
            // n = 5, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8b542464             | mov                 edx, dword ptr [esp + 0x64]
            //   83c404               | add                 esp, 4
            //   52                   | push                edx

        $sequence_5 = { 8b5718 6a00 8d471c 50 8d4e1c 895618 }
            // n = 6, score = 100
            //   8b5718               | mov                 edx, dword ptr [edi + 0x18]
            //   6a00                 | push                0
            //   8d471c               | lea                 eax, [edi + 0x1c]
            //   50                   | push                eax
            //   8d4e1c               | lea                 ecx, [esi + 0x1c]
            //   895618               | mov                 dword ptr [esi + 0x18], edx

        $sequence_6 = { 6a01 66894702 ff15???????? 66894704 33c9 33c0 33d2 }
            // n = 7, score = 100
            //   6a01                 | push                1
            //   66894702             | mov                 word ptr [edi + 2], ax
            //   ff15????????         |                     
            //   66894704             | mov                 word ptr [edi + 4], ax
            //   33c9                 | xor                 ecx, ecx
            //   33c0                 | xor                 eax, eax
            //   33d2                 | xor                 edx, edx

        $sequence_7 = { 5d c6802001000001 898824010000 898828010000 }
            // n = 4, score = 100
            //   5d                   | pop                 ebp
            //   c6802001000001       | mov                 byte ptr [eax + 0x120], 1
            //   898824010000         | mov                 dword ptr [eax + 0x124], ecx
            //   898828010000         | mov                 dword ptr [eax + 0x128], ecx

        $sequence_8 = { 64a300000000 e8???????? e8???????? e8???????? e8???????? e8???????? 8d44240c }
            // n = 7, score = 100
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   8d44240c             | lea                 eax, [esp + 0xc]

        $sequence_9 = { e8???????? be06000000 3974240c 7548 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   be06000000           | mov                 esi, 6
            //   3974240c             | cmp                 dword ptr [esp + 0xc], esi
            //   7548                 | jne                 0x4a

    condition:
        7 of them and filesize < 394240
}