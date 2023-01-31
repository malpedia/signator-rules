rule win_anatova_ransom_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.anatova_ransom."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.anatova_ransom"
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
        $sequence_0 = { 4c89d1 4c89da 4c8b1d???????? 41ffd3 488b45a8 4989c3 488b45b0 }
            // n = 7, score = 100
            //   4c89d1               | cmp                 eax, 0
            //   4c89da               | dec                 esp
            //   4c8b1d????????       |                     
            //   41ffd3               | mov                 ecx, edx
            //   488b45a8             | dec                 esp
            //   4989c3               | mov                 edx, ebx
            //   488b45b0             | dec                 eax

        $sequence_1 = { 83c101 668908 8b45ec c1e801 8945ec e9???????? }
            // n = 6, score = 100
            //   83c101               | mov                 eax, 0
            //   668908               | add                 byte ptr [eax], al
            //   8b45ec               | add                 byte ptr [eax], al
            //   c1e801               | dec                 eax
            //   8945ec               | mov                 dword ptr [ebp - 0x20], eax
            //   e9????????           |                     

        $sequence_2 = { 48899568ffffff 4c89d1 e8???????? 488b8d68ffffff 8901 488b8d70ffffff }
            // n = 6, score = 100
            //   48899568ffffff       | mov                 eax, dword ptr [ebp - 0x138]
            //   4c89d1               | dec                 esp
            //   e8????????           |                     
            //   488b8d68ffffff       | mov                 edx, ebx
            //   8901                 | inc                 ecx
            //   488b8d70ffffff       | call                ebx

        $sequence_3 = { 83f800 0f86c9050000 b80a000000 4989c3 488d0503610000 4989c2 }
            // n = 6, score = 100
            //   83f800               | add                 eax, 1
            //   0f86c9050000         | mov                 dword ptr [ebp - 0x30], eax
            //   b80a000000           | jge                 0xfffffdc5
            //   4989c3               | cmp                 eax, 3
            //   488d0503610000       | jg                  0x154
            //   4989c2               | cmp                 eax, 3

        $sequence_4 = { 0f84db000000 488b45e0 4883f800 0f84cd000000 488b45e8 4883f800 0f84bf000000 }
            // n = 7, score = 100
            //   0f84db000000         | mov                 edx, eax
            //   488b45e0             | dec                 eax
            //   4883f800             | mov                 dword ptr [ebp - 8], eax
            //   0f84cd000000         | dec                 eax
            //   488b45e8             | mov                 eax, dword ptr [ebp + 0x28]
            //   4883f800             | dec                 eax
            //   0f84bf000000         | mov                 dword ptr [ebp - 0x10], ecx

        $sequence_5 = { 884591 b80e000000 884592 b803000000 884593 b80a000000 884594 }
            // n = 7, score = 100
            //   884591               | mov                 dword ptr [esp + 0x30], eax
            //   b80e000000           | mov                 eax, 0x80
            //   884592               | cmp                 eax, 0
            //   b803000000           | je                  0xd0b
            //   884593               | dec                 eax
            //   b80a000000           | mov                 eax, 0x100000
            //   884594               | add                 byte ptr [eax], al

        $sequence_6 = { 8b4df8 01c8 4863c0 488b4d20 4801c1 }
            // n = 5, score = 100
            //   8b4df8               | mov                 eax, dword ptr [ebp - 0x10]
            //   01c8                 | dec                 eax
            //   4863c0               | cmp                 eax, 0
            //   488b4d20             | jbe                 0xf34
            //   4801c1               | dec                 eax

        $sequence_7 = { 89856cffffff 488b45d0 4989c2 4c89d1 }
            // n = 4, score = 100
            //   89856cffffff         | dec                 eax
            //   488b45d0             | lea                 eax, [0x39d5]
            //   4989c2               | dec                 eax
            //   4c89d1               | mov                 dword ptr [ebp - 0x100], eax

        $sequence_8 = { 4c89d1 4c89da e8???????? 488b45a0 488d4dc0 4989c8 }
            // n = 6, score = 100
            //   4c89d1               | ret                 
            //   4c89da               | push                ebp
            //   e8????????           |                     
            //   488b45a0             | dec                 eax
            //   488d4dc0             | mov                 ebp, esp
            //   4989c8               | dec                 eax

        $sequence_9 = { 83f800 0f8485fbffff 83f801 0f84a1fbffff }
            // n = 4, score = 100
            //   83f800               | mov                 ecx, edx
            //   0f8485fbffff         | dec                 eax
            //   83f801               | mov                 ecx, dword ptr [ebp - 0xa0]
            //   0f84a1fbffff         | mov                 dword ptr [ecx], eax

    condition:
        7 of them and filesize < 671744
}