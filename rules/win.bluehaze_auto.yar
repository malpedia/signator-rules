rule win_bluehaze_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.bluehaze."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bluehaze"
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
        $sequence_0 = { 55 8bec 56 8b7508 8b06 8b5014 68bc020000 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8b5014               | mov                 edx, dword ptr [eax + 0x14]
            //   68bc020000           | push                0x2bc

        $sequence_1 = { 8b5104 83c404 894208 eb5d 894104 8b0f 8908 }
            // n = 7, score = 100
            //   8b5104               | mov                 edx, dword ptr [ecx + 4]
            //   83c404               | add                 esp, 4
            //   894208               | mov                 dword ptr [edx + 8], eax
            //   eb5d                 | jmp                 0x5f
            //   894104               | mov                 dword ptr [ecx + 4], eax
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   8908                 | mov                 dword ptr [eax], ecx

        $sequence_2 = { 720f 8b8d54ffffff 51 e8???????? 83c404 8d8d84feffff c645fc00 }
            // n = 7, score = 100
            //   720f                 | jb                  0x11
            //   8b8d54ffffff         | mov                 ecx, dword ptr [ebp - 0xac]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8d8d84feffff         | lea                 ecx, [ebp - 0x17c]
            //   c645fc00             | mov                 byte ptr [ebp - 4], 0

        $sequence_3 = { f6855cffffff01 c645fc08 7411 8b952cffffff 8b02 50 e8???????? }
            // n = 7, score = 100
            //   f6855cffffff01       | test                byte ptr [ebp - 0xa4], 1
            //   c645fc08             | mov                 byte ptr [ebp - 4], 8
            //   7411                 | je                  0x13
            //   8b952cffffff         | mov                 edx, dword ptr [ebp - 0xd4]
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_4 = { 8b10 6a01 ffd2 8d4e2c e8???????? 8b7e2c 57 }
            // n = 7, score = 100
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   6a01                 | push                1
            //   ffd2                 | call                edx
            //   8d4e2c               | lea                 ecx, [esi + 0x2c]
            //   e8????????           |                     
            //   8b7e2c               | mov                 edi, dword ptr [esi + 0x2c]
            //   57                   | push                edi

        $sequence_5 = { 8bc8 8b01 385845 74f7 898d44ffffff eb2b 8b4204 }
            // n = 7, score = 100
            //   8bc8                 | mov                 ecx, eax
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   385845               | cmp                 byte ptr [eax + 0x45], bl
            //   74f7                 | je                  0xfffffff9
            //   898d44ffffff         | mov                 dword ptr [ebp - 0xbc], ecx
            //   eb2b                 | jmp                 0x2d
            //   8b4204               | mov                 eax, dword ptr [edx + 4]

        $sequence_6 = { 894008 8b4604 c6402c01 8b4e04 c6412d01 eb2b 8d55f0 }
            // n = 7, score = 100
            //   894008               | mov                 dword ptr [eax + 8], eax
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   c6402c01             | mov                 byte ptr [eax + 0x2c], 1
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   c6412d01             | mov                 byte ptr [ecx + 0x2d], 1
            //   eb2b                 | jmp                 0x2d
            //   8d55f0               | lea                 edx, [ebp - 0x10]

        $sequence_7 = { 8b4510 6aff 8d4e38 53 c741140f000000 895910 50 }
            // n = 7, score = 100
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   6aff                 | push                -1
            //   8d4e38               | lea                 ecx, [esi + 0x38]
            //   53                   | push                ebx
            //   c741140f000000       | mov                 dword ptr [ecx + 0x14], 0xf
            //   895910               | mov                 dword ptr [ecx + 0x10], ebx
            //   50                   | push                eax

        $sequence_8 = { bf01000000 eb1f 397590 741d 3bce 7419 80fb78 }
            // n = 7, score = 100
            //   bf01000000           | mov                 edi, 1
            //   eb1f                 | jmp                 0x21
            //   397590               | cmp                 dword ptr [ebp - 0x70], esi
            //   741d                 | je                  0x1f
            //   3bce                 | cmp                 ecx, esi
            //   7419                 | je                  0x1b
            //   80fb78               | cmp                 bl, 0x78

        $sequence_9 = { 8bc8 e8???????? eb02 33c0 894628 8bc6 8b4df4 }
            // n = 7, score = 100
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   894628               | mov                 dword ptr [esi + 0x28], eax
            //   8bc6                 | mov                 eax, esi
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

    condition:
        7 of them and filesize < 424960
}