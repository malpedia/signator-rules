rule win_grok_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.grok."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.grok"
        malpedia_rule_date = "20211007"
        malpedia_hash = "e5b790e0f888f252d49063a1251ca60ec2832535"
        malpedia_version = "20211008"
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
        $sequence_0 = { 83782800 7416 8b45c8 8b4028 ff7028 ff55f4 }
            // n = 6, score = 400
            //   83782800             | cmp                 dword ptr [eax + 0x28], 0
            //   7416                 | je                  0x18
            //   8b45c8               | mov                 eax, dword ptr [ebp - 0x38]
            //   8b4028               | mov                 eax, dword ptr [eax + 0x28]
            //   ff7028               | push                dword ptr [eax + 0x28]
            //   ff55f4               | call                dword ptr [ebp - 0xc]

        $sequence_1 = { eb20 8bfe c1e702 be44646b20 56 57 }
            // n = 6, score = 400
            //   eb20                 | jmp                 0x22
            //   8bfe                 | mov                 edi, esi
            //   c1e702               | shl                 edi, 2
            //   be44646b20           | mov                 esi, 0x206b6444
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_2 = { 740f 80f9bf 740a 83f807 757e 803ec7 7579 }
            // n = 7, score = 400
            //   740f                 | je                  0x11
            //   80f9bf               | cmp                 cl, 0xbf
            //   740a                 | je                  0xc
            //   83f807               | cmp                 eax, 7
            //   757e                 | jne                 0x80
            //   803ec7               | cmp                 byte ptr [esi], 0xc7
            //   7579                 | jne                 0x7b

        $sequence_3 = { c6854efeffff6f c6854ffeffff63 c68550feffff61 c68551feffff6c c68552feffff5f c68553feffff75 c68554feffff6e }
            // n = 7, score = 400
            //   c6854efeffff6f       | mov                 byte ptr [ebp - 0x1b2], 0x6f
            //   c6854ffeffff63       | mov                 byte ptr [ebp - 0x1b1], 0x63
            //   c68550feffff61       | mov                 byte ptr [ebp - 0x1b0], 0x61
            //   c68551feffff6c       | mov                 byte ptr [ebp - 0x1af], 0x6c
            //   c68552feffff5f       | mov                 byte ptr [ebp - 0x1ae], 0x5f
            //   c68553feffff75       | mov                 byte ptr [ebp - 0x1ad], 0x75
            //   c68554feffff6e       | mov                 byte ptr [ebp - 0x1ac], 0x6e

        $sequence_4 = { 895df0 8d7df4 ab a1???????? 3998bc010000 }
            // n = 5, score = 400
            //   895df0               | mov                 dword ptr [ebp - 0x10], ebx
            //   8d7df4               | lea                 edi, dword ptr [ebp - 0xc]
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   a1????????           |                     
            //   3998bc010000         | cmp                 dword ptr [eax + 0x1bc], ebx

        $sequence_5 = { 8b3d???????? 8d45f0 50 ffd7 ff750c 8d45f8 }
            // n = 6, score = 400
            //   8b3d????????         |                     
            //   8d45f0               | lea                 eax, dword ptr [ebp - 0x10]
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   8d45f8               | lea                 eax, dword ptr [ebp - 8]

        $sequence_6 = { ff55f4 8b45c8 8b4028 83603800 8365d000 8b45c8 8b4028 }
            // n = 7, score = 400
            //   ff55f4               | call                dword ptr [ebp - 0xc]
            //   8b45c8               | mov                 eax, dword ptr [ebp - 0x38]
            //   8b4028               | mov                 eax, dword ptr [eax + 0x28]
            //   83603800             | and                 dword ptr [eax + 0x38], 0
            //   8365d000             | and                 dword ptr [ebp - 0x30], 0
            //   8b45c8               | mov                 eax, dword ptr [ebp - 0x38]
            //   8b4028               | mov                 eax, dword ptr [eax + 0x28]

        $sequence_7 = { 6a20 56 c744241c01000000 ff15???????? 8b0d???????? 894138 }
            // n = 6, score = 400
            //   6a20                 | push                0x20
            //   56                   | push                esi
            //   c744241c01000000     | mov                 dword ptr [esp + 0x1c], 1
            //   ff15????????         |                     
            //   8b0d????????         |                     
            //   894138               | mov                 dword ptr [ecx + 0x38], eax

        $sequence_8 = { 8b4e04 8901 894804 ff4f14 7408 8b4514 832000 }
            // n = 7, score = 400
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   8901                 | mov                 dword ptr [ecx], eax
            //   894804               | mov                 dword ptr [eax + 4], ecx
            //   ff4f14               | dec                 dword ptr [edi + 0x14]
            //   7408                 | je                  0xa
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   832000               | and                 dword ptr [eax], 0

        $sequence_9 = { 6a01 6a04 56 8945e4 56 8d45f4 }
            // n = 6, score = 400
            //   6a01                 | push                1
            //   6a04                 | push                4
            //   56                   | push                esi
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   56                   | push                esi
            //   8d45f4               | lea                 eax, dword ptr [ebp - 0xc]

    condition:
        7 of them and filesize < 84992
}