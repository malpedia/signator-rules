rule win_industroyer2_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.industroyer2."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.industroyer2"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
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
        $sequence_0 = { 0355fc 0fb64201 8b4dfc 8d540101 8955fc e9???????? 8b4518 }
            // n = 7, score = 100
            //   0355fc               | add                 edx, dword ptr [ebp - 4]
            //   0fb64201             | movzx               eax, byte ptr [edx + 1]
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8d540101             | lea                 edx, [ecx + eax + 1]
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   e9????????           |                     
            //   8b4518               | mov                 eax, dword ptr [ebp + 0x18]

        $sequence_1 = { c6811c00010000 8b55fc c6824400010000 8b45fc }
            // n = 4, score = 100
            //   c6811c00010000       | mov                 byte ptr [ecx + 0x1001c], 0
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   c6824400010000       | mov                 byte ptr [edx + 0x10044], 0
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_2 = { 888245000100 8b4d08 0fb69145000100 85d2 7409 }
            // n = 5, score = 100
            //   888245000100         | mov                 byte ptr [edx + 0x10045], al
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   0fb69145000100       | movzx               edx, byte ptr [ecx + 0x10045]
            //   85d2                 | test                edx, edx
            //   7409                 | je                  0xb

        $sequence_3 = { 898538ffffff 8b8d38ffffff 51 ff15???????? 898534ffffff 8b55fc }
            // n = 6, score = 100
            //   898538ffffff         | mov                 dword ptr [ebp - 0xc8], eax
            //   8b8d38ffffff         | mov                 ecx, dword ptr [ebp - 0xc8]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   898534ffffff         | mov                 dword ptr [ebp - 0xcc], eax
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]

        $sequence_4 = { 83c408 8b45fc 8be5 5d c20400 ff25???????? ff25???????? }
            // n = 7, score = 100
            //   83c408               | add                 esp, 8
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   ff25????????         |                     
            //   ff25????????         |                     

        $sequence_5 = { 8b4db4 51 0fb655e5 52 0fb645e7 50 0fb64de6 }
            // n = 7, score = 100
            //   8b4db4               | mov                 ecx, dword ptr [ebp - 0x4c]
            //   51                   | push                ecx
            //   0fb655e5             | movzx               edx, byte ptr [ebp - 0x1b]
            //   52                   | push                edx
            //   0fb645e7             | movzx               eax, byte ptr [ebp - 0x19]
            //   50                   | push                eax
            //   0fb64de6             | movzx               ecx, byte ptr [ebp - 0x1a]

        $sequence_6 = { 83c101 894dfc 83bd4cffffff01 7509 c745d001000000 eb07 }
            // n = 6, score = 100
            //   83c101               | add                 ecx, 1
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   83bd4cffffff01       | cmp                 dword ptr [ebp - 0xb4], 1
            //   7509                 | jne                 0xb
            //   c745d001000000       | mov                 dword ptr [ebp - 0x30], 1
            //   eb07                 | jmp                 9

        $sequence_7 = { 8b4dec 894dfc 8b550c 52 8b4dfc e8???????? 8b4dfc }
            // n = 7, score = 100
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   52                   | push                edx
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   e8????????           |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_8 = { eb07 c745d400000000 8b55fc 52 ff15???????? 6a00 ff15???????? }
            // n = 7, score = 100
            //   eb07                 | jmp                 9
            //   c745d400000000       | mov                 dword ptr [ebp - 0x2c], 0
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_9 = { 7412 8b4d08 51 e8???????? 0fb6d0 85d2 7502 }
            // n = 7, score = 100
            //   7412                 | je                  0x14
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   0fb6d0               | movzx               edx, al
            //   85d2                 | test                edx, edx
            //   7502                 | jne                 4

    condition:
        7 of them and filesize < 100352
}