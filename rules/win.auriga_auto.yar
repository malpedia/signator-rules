rule win_auriga_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.auriga."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.auriga"
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
        $sequence_0 = { 897de8 0f8ccc000000 8b733c ff7618 ff15???????? 84c0 0f84b8000000 }
            // n = 7, score = 100
            //   897de8               | mov                 dword ptr [ebp - 0x18], edi
            //   0f8ccc000000         | jl                  0xd2
            //   8b733c               | mov                 esi, dword ptr [ebx + 0x3c]
            //   ff7618               | push                dword ptr [esi + 0x18]
            //   ff15????????         |                     
            //   84c0                 | test                al, al
            //   0f84b8000000         | je                  0xbe

        $sequence_1 = { 8b8504fcffff 8d8405fcfbffff 50 ffb5e4fbffff e8???????? }
            // n = 5, score = 100
            //   8b8504fcffff         | mov                 eax, dword ptr [ebp - 0x3fc]
            //   8d8405fcfbffff       | lea                 eax, [ebp + eax - 0x404]
            //   50                   | push                eax
            //   ffb5e4fbffff         | push                dword ptr [ebp - 0x41c]
            //   e8????????           |                     

        $sequence_2 = { 8d45dc 50 ff15???????? 68???????? 68???????? 6a01 8d45dc }
            // n = 7, score = 100
            //   8d45dc               | lea                 eax, [ebp - 0x24]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   68????????           |                     
            //   68????????           |                     
            //   6a01                 | push                1
            //   8d45dc               | lea                 eax, [ebp - 0x24]

        $sequence_3 = { 884708 804e0340 5f 53 ff7508 ff15???????? 5e }
            // n = 7, score = 100
            //   884708               | mov                 byte ptr [edi + 8], al
            //   804e0340             | or                  byte ptr [esi + 3], 0x40
            //   5f                   | pop                 edi
            //   53                   | push                ebx
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   5e                   | pop                 esi

        $sequence_4 = { 6bc018 e9???????? 3d09010000 740b }
            // n = 4, score = 100
            //   6bc018               | imul                eax, eax, 0x18
            //   e9????????           |                     
            //   3d09010000           | cmp                 eax, 0x109
            //   740b                 | je                  0xd

        $sequence_5 = { ffb5f4fbffff ffd6 33c0 8b4dfc 5f }
            // n = 5, score = 100
            //   ffb5f4fbffff         | push                dword ptr [ebp - 0x40c]
            //   ffd6                 | call                esi
            //   33c0                 | xor                 eax, eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   5f                   | pop                 edi

        $sequence_6 = { 50 ffd3 8b45fc 85c0 7539 ff750c }
            // n = 6, score = 100
            //   50                   | push                eax
            //   ffd3                 | call                ebx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   85c0                 | test                eax, eax
            //   7539                 | jne                 0x3b
            //   ff750c               | push                dword ptr [ebp + 0xc]

        $sequence_7 = { ff75f4 ff75fc e8???????? 6bff0c 57 ff75ec }
            // n = 6, score = 100
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   6bff0c               | imul                edi, edi, 0xc
            //   57                   | push                edi
            //   ff75ec               | push                dword ptr [ebp - 0x14]

        $sequence_8 = { 3bfa 894df4 7291 eb03 ff45fc }
            // n = 5, score = 100
            //   3bfa                 | cmp                 edi, edx
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   7291                 | jb                  0xffffff93
            //   eb03                 | jmp                 5
            //   ff45fc               | inc                 dword ptr [ebp - 4]

        $sequence_9 = { 8b3c30 ff45ec eba1 8bc6 eb02 }
            // n = 5, score = 100
            //   8b3c30               | mov                 edi, dword ptr [eax + esi]
            //   ff45ec               | inc                 dword ptr [ebp - 0x14]
            //   eba1                 | jmp                 0xffffffa3
            //   8bc6                 | mov                 eax, esi
            //   eb02                 | jmp                 4

    condition:
        7 of them and filesize < 75776
}