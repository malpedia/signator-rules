rule win_shareip_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.shareip."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shareip"
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
        $sequence_0 = { 83c8ff e9???????? 8d44247c 50 e8???????? c744247ca0024500 8d4c2428 }
            // n = 7, score = 100
            //   83c8ff               | or                  eax, 0xffffffff
            //   e9????????           |                     
            //   8d44247c             | lea                 eax, [esp + 0x7c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   c744247ca0024500     | mov                 dword ptr [esp + 0x7c], 0x4502a0
            //   8d4c2428             | lea                 ecx, [esp + 0x28]

        $sequence_1 = { 03c5 03d0 c1c213 8bc7 33c6 8b6920 23c2 }
            // n = 7, score = 100
            //   03c5                 | add                 eax, ebp
            //   03d0                 | add                 edx, eax
            //   c1c213               | rol                 edx, 0x13
            //   8bc7                 | mov                 eax, edi
            //   33c6                 | xor                 eax, esi
            //   8b6920               | mov                 ebp, dword ptr [ecx + 0x20]
            //   23c2                 | and                 eax, edx

        $sequence_2 = { 8b5614 50 51 52 6a00 8bce e8???????? }
            // n = 7, score = 100
            //   8b5614               | mov                 edx, dword ptr [esi + 0x14]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   52                   | push                edx
            //   6a00                 | push                0
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_3 = { 395e34 7205 8b4620 eb03 8d4620 50 e8???????? }
            // n = 7, score = 100
            //   395e34               | cmp                 dword ptr [esi + 0x34], ebx
            //   7205                 | jb                  7
            //   8b4620               | mov                 eax, dword ptr [esi + 0x20]
            //   eb03                 | jmp                 5
            //   8d4620               | lea                 eax, [esi + 0x20]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_4 = { 3bfa 7605 e8???????? 55 53 57 56 }
            // n = 7, score = 100
            //   3bfa                 | cmp                 edi, edx
            //   7605                 | jbe                 7
            //   e8????????           |                     
            //   55                   | push                ebp
            //   53                   | push                ebx
            //   57                   | push                edi
            //   56                   | push                esi

        $sequence_5 = { e8???????? 83c404 8bc6 e9???????? 8d4c2414 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8bc6                 | mov                 eax, esi
            //   e9????????           |                     
            //   8d4c2414             | lea                 ecx, [esp + 0x14]

        $sequence_6 = { 8b4e0c 885917 0fb64624 8b560c 884218 0fb65625 8b4e0c }
            // n = 7, score = 100
            //   8b4e0c               | mov                 ecx, dword ptr [esi + 0xc]
            //   885917               | mov                 byte ptr [ecx + 0x17], bl
            //   0fb64624             | movzx               eax, byte ptr [esi + 0x24]
            //   8b560c               | mov                 edx, dword ptr [esi + 0xc]
            //   884218               | mov                 byte ptr [edx + 0x18], al
            //   0fb65625             | movzx               edx, byte ptr [esi + 0x25]
            //   8b4e0c               | mov                 ecx, dword ptr [esi + 0xc]

        $sequence_7 = { e8???????? 83c404 8d44243c e8???????? 8bc6 e9???????? 83bc24fc00000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8d44243c             | lea                 eax, [esp + 0x3c]
            //   e8????????           |                     
            //   8bc6                 | mov                 eax, esi
            //   e9????????           |                     
            //   83bc24fc00000000     | cmp                 dword ptr [esp + 0xfc], 0

        $sequence_8 = { 33d2 6689544c3c f6463810 68???????? 51 7412 8d442444 }
            // n = 7, score = 100
            //   33d2                 | xor                 edx, edx
            //   6689544c3c           | mov                 word ptr [esp + ecx*2 + 0x3c], dx
            //   f6463810             | test                byte ptr [esi + 0x38], 0x10
            //   68????????           |                     
            //   51                   | push                ecx
            //   7412                 | je                  0x14
            //   8d442444             | lea                 eax, [esp + 0x44]

        $sequence_9 = { 83bc249400000000 7412 8b942484000000 8b02 8d8c2484000000 ffd0 8b8424a0000000 }
            // n = 7, score = 100
            //   83bc249400000000     | cmp                 dword ptr [esp + 0x94], 0
            //   7412                 | je                  0x14
            //   8b942484000000       | mov                 edx, dword ptr [esp + 0x84]
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   8d8c2484000000       | lea                 ecx, [esp + 0x84]
            //   ffd0                 | call                eax
            //   8b8424a0000000       | mov                 eax, dword ptr [esp + 0xa0]

    condition:
        7 of them and filesize < 811008
}