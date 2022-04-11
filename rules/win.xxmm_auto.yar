rule win_xxmm_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.xxmm."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xxmm"
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
        $sequence_0 = { 394de0 740f 394dec 740a 394de8 7405 394ddc }
            // n = 7, score = 600
            //   394de0               | cmp                 dword ptr [ebp - 0x20], ecx
            //   740f                 | je                  0x11
            //   394dec               | cmp                 dword ptr [ebp - 0x14], ecx
            //   740a                 | je                  0xc
            //   394de8               | cmp                 dword ptr [ebp - 0x18], ecx
            //   7405                 | je                  7
            //   394ddc               | cmp                 dword ptr [ebp - 0x24], ecx

        $sequence_1 = { 8a16 c1cf0d 80fa61 0fb6d2 7206 8d7c17e0 eb02 }
            // n = 7, score = 600
            //   8a16                 | mov                 dl, byte ptr [esi]
            //   c1cf0d               | ror                 edi, 0xd
            //   80fa61               | cmp                 dl, 0x61
            //   0fb6d2               | movzx               edx, dl
            //   7206                 | jb                  8
            //   8d7c17e0             | lea                 edi, dword ptr [edi + edx - 0x20]
            //   eb02                 | jmp                 4

        $sequence_2 = { 56 57 33ff 8bf0 397d08 0f84bc000000 397d10 }
            // n = 7, score = 600
            //   56                   | push                esi
            //   57                   | push                edi
            //   33ff                 | xor                 edi, edi
            //   8bf0                 | mov                 esi, eax
            //   397d08               | cmp                 dword ptr [ebp + 8], edi
            //   0f84bc000000         | je                  0xc2
            //   397d10               | cmp                 dword ptr [ebp + 0x10], edi

        $sequence_3 = { eb0f 81fbf232f60e 7507 8b00 03c1 8945e8 }
            // n = 6, score = 600
            //   eb0f                 | jmp                 0x11
            //   81fbf232f60e         | cmp                 ebx, 0xef632f2
            //   7507                 | jne                 9
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   03c1                 | add                 eax, ecx
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax

        $sequence_4 = { 8d1c0a 895d14 8a1b 895510 8a10 8818 8b5d14 }
            // n = 7, score = 600
            //   8d1c0a               | lea                 ebx, dword ptr [edx + ecx]
            //   895d14               | mov                 dword ptr [ebp + 0x14], ebx
            //   8a1b                 | mov                 bl, byte ptr [ebx]
            //   895510               | mov                 dword ptr [ebp + 0x10], edx
            //   8a10                 | mov                 dl, byte ptr [eax]
            //   8818                 | mov                 byte ptr [eax], bl
            //   8b5d14               | mov                 ebx, dword ptr [ebp + 0x14]

        $sequence_5 = { 50 ff75fc ff55e0 8b55fc 8907 8b45f4 }
            // n = 6, score = 600
            //   50                   | push                eax
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff55e0               | call                dword ptr [ebp - 0x20]
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8907                 | mov                 dword ptr [edi], eax
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_6 = { 0f84ab000000 6800010000 e8???????? 59 ff7514 8bc8 ff7510 }
            // n = 7, score = 600
            //   0f84ab000000         | je                  0xb1
            //   6800010000           | push                0x100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   8bc8                 | mov                 ecx, eax
            //   ff7510               | push                dword ptr [ebp + 0x10]

        $sequence_7 = { 8bcf e8???????? 8b4df8 0fb711 }
            // n = 4, score = 600
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   0fb711               | movzx               edx, word ptr [ecx]

        $sequence_8 = { 8bcf e8???????? 8b7324 03c7 8bcf }
            // n = 5, score = 600
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   8b7324               | mov                 esi, dword ptr [ebx + 0x24]
            //   03c7                 | add                 eax, edi
            //   8bcf                 | mov                 ecx, edi

        $sequence_9 = { 807c01ff00 7407 b890040000 eb02 33c0 5b 5d }
            // n = 7, score = 600
            //   807c01ff00           | cmp                 byte ptr [ecx + eax - 1], 0
            //   7407                 | je                  9
            //   b890040000           | mov                 eax, 0x490
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp

    condition:
        7 of them and filesize < 540672
}