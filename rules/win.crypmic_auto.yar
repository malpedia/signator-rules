rule win_crypmic_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.crypmic."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crypmic"
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
        $sequence_0 = { c1c003 8d4abf 6683f919 0fb7ca 7703 }
            // n = 5, score = 300
            //   c1c003               | rol                 eax, 3
            //   8d4abf               | lea                 ecx, [edx - 0x41]
            //   6683f919             | cmp                 cx, 0x19
            //   0fb7ca               | movzx               ecx, dx
            //   7703                 | ja                  5

        $sequence_1 = { 8bf0 8d9b00000000 0fb707 6685c0 }
            // n = 4, score = 300
            //   8bf0                 | mov                 esi, eax
            //   8d9b00000000         | lea                 ebx, [ebx]
            //   0fb707               | movzx               eax, word ptr [edi]
            //   6685c0               | test                ax, ax

        $sequence_2 = { 8b55fc 5f 8b4224 5e 8d0458 5b }
            // n = 6, score = 300
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   5f                   | pop                 edi
            //   8b4224               | mov                 eax, dword ptr [edx + 0x24]
            //   5e                   | pop                 esi
            //   8d0458               | lea                 eax, [eax + ebx*2]
            //   5b                   | pop                 ebx

        $sequence_3 = { 6a00 8d4df8 51 ff7508 c745f800000000 50 }
            // n = 6, score = 300
            //   6a00                 | push                0
            //   8d4df8               | lea                 ecx, [ebp - 8]
            //   51                   | push                ecx
            //   ff7508               | push                dword ptr [ebp + 8]
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0
            //   50                   | push                eax

        $sequence_4 = { 57 6a00 ff7604 ffd0 8b460c }
            // n = 5, score = 300
            //   57                   | push                edi
            //   6a00                 | push                0
            //   ff7604               | push                dword ptr [esi + 4]
            //   ffd0                 | call                eax
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]

        $sequence_5 = { 8b45f2 0faf45f0 0fb7c0 83f801 7504 8bd8 eb33 }
            // n = 7, score = 300
            //   8b45f2               | mov                 eax, dword ptr [ebp - 0xe]
            //   0faf45f0             | imul                eax, dword ptr [ebp - 0x10]
            //   0fb7c0               | movzx               eax, ax
            //   83f801               | cmp                 eax, 1
            //   7504                 | jne                 6
            //   8bd8                 | mov                 ebx, eax
            //   eb33                 | jmp                 0x35

        $sequence_6 = { 8b4de4 894f04 8b4de8 894f08 668b4df0 66894f0c 668b45f2 }
            // n = 7, score = 300
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]
            //   894f04               | mov                 dword ptr [edi + 4], ecx
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   894f08               | mov                 dword ptr [edi + 8], ecx
            //   668b4df0             | mov                 cx, word ptr [ebp - 0x10]
            //   66894f0c             | mov                 word ptr [edi + 0xc], cx
            //   668b45f2             | mov                 ax, word ptr [ebp - 0xe]

        $sequence_7 = { 5d c3 33c9 33c0 663bcf 741f 0fb7cf }
            // n = 7, score = 300
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   33c9                 | xor                 ecx, ecx
            //   33c0                 | xor                 eax, eax
            //   663bcf               | cmp                 cx, di
            //   741f                 | je                  0x21
            //   0fb7cf               | movzx               ecx, di

        $sequence_8 = { 33c0 8bcf 66894302 e8???????? }
            // n = 4, score = 300
            //   33c0                 | xor                 eax, eax
            //   8bcf                 | mov                 ecx, edi
            //   66894302             | mov                 word ptr [ebx + 2], ax
            //   e8????????           |                     

        $sequence_9 = { 05e0ff0000 663bd0 7419 837df800 7444 8b55fc }
            // n = 6, score = 300
            //   05e0ff0000           | add                 eax, 0xffe0
            //   663bd0               | cmp                 dx, ax
            //   7419                 | je                  0x1b
            //   837df800             | cmp                 dword ptr [ebp - 8], 0
            //   7444                 | je                  0x46
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]

    condition:
        7 of them and filesize < 81920
}