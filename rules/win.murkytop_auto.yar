rule win_murkytop_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.murkytop."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.murkytop"
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
        $sequence_0 = { 40 80b960cf410000 74e8 8a13 0fb6ca 0fbe8960cf4100 }
            // n = 6, score = 100
            //   40                   | inc                 eax
            //   80b960cf410000       | cmp                 byte ptr [ecx + 0x41cf60], 0
            //   74e8                 | je                  0xffffffea
            //   8a13                 | mov                 dl, byte ptr [ebx]
            //   0fb6ca               | movzx               ecx, dl
            //   0fbe8960cf4100       | movsx               ecx, byte ptr [ecx + 0x41cf60]

        $sequence_1 = { 1b5c1104 8b483c 51 8b5038 }
            // n = 4, score = 100
            //   1b5c1104             | sbb                 ebx, dword ptr [ecx + edx + 4]
            //   8b483c               | mov                 ecx, dword ptr [eax + 0x3c]
            //   51                   | push                ecx
            //   8b5038               | mov                 edx, dword ptr [eax + 0x38]

        $sequence_2 = { 50 68???????? e8???????? 83c408 8b5d08 33c0 8945e8 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   68????????           |                     
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   33c0                 | xor                 eax, eax
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax

        $sequence_3 = { 83c404 3dffff0000 7d49 8b3d???????? }
            // n = 4, score = 100
            //   83c404               | add                 esp, 4
            //   3dffff0000           | cmp                 eax, 0xffff
            //   7d49                 | jge                 0x4b
            //   8b3d????????         |                     

        $sequence_4 = { 68???????? e8???????? 83c404 3975f4 7623 }
            // n = 5, score = 100
            //   68????????           |                     
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   3975f4               | cmp                 dword ptr [ebp - 0xc], esi
            //   7623                 | jbe                 0x25

        $sequence_5 = { 0f8ceffcffff 8b4de8 51 68???????? }
            // n = 4, score = 100
            //   0f8ceffcffff         | jl                  0xfffffcf5
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   51                   | push                ecx
            //   68????????           |                     

        $sequence_6 = { 897da0 8955a4 6a00 e8???????? 83c404 8945d8 8955dc }
            // n = 7, score = 100
            //   897da0               | mov                 dword ptr [ebp - 0x60], edi
            //   8955a4               | mov                 dword ptr [ebp - 0x5c], edx
            //   6a00                 | push                0
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   8955dc               | mov                 dword ptr [ebp - 0x24], edx

        $sequence_7 = { 8bda 66c1e008 c1fb18 0fb7c0 }
            // n = 4, score = 100
            //   8bda                 | mov                 ebx, edx
            //   66c1e008             | shl                 ax, 8
            //   c1fb18               | sar                 ebx, 0x18
            //   0fb7c0               | movzx               eax, ax

        $sequence_8 = { 8b450c 8b80f0ce4100 3bf0 7e44 83ee07 eb3f }
            // n = 6, score = 100
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8b80f0ce4100         | mov                 eax, dword ptr [eax + 0x41cef0]
            //   3bf0                 | cmp                 esi, eax
            //   7e44                 | jle                 0x46
            //   83ee07               | sub                 esi, 7
            //   eb3f                 | jmp                 0x41

        $sequence_9 = { 52 8945e4 8b45f8 6a00 50 c745e001000000 894de8 }
            // n = 7, score = 100
            //   52                   | push                edx
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   c745e001000000       | mov                 dword ptr [ebp - 0x20], 1
            //   894de8               | mov                 dword ptr [ebp - 0x18], ecx

    condition:
        7 of them and filesize < 294912
}