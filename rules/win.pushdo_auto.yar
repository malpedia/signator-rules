rule win_pushdo_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.pushdo."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pushdo"
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
        $sequence_0 = { f7f9 33c9 ba88020000 f7e2 0f90c1 }
            // n = 5, score = 1200
            //   f7f9                 | idiv                ecx
            //   33c9                 | xor                 ecx, ecx
            //   ba88020000           | mov                 edx, 0x288
            //   f7e2                 | mul                 edx
            //   0f90c1               | seto                cl

        $sequence_1 = { 50 ff15???????? 33d2 b9ffff0000 f7f1 }
            // n = 5, score = 1200
            //   50                   | push                eax
            //   ff15????????         |                     
            //   33d2                 | xor                 edx, edx
            //   b9ffff0000           | mov                 ecx, 0xffff
            //   f7f1                 | div                 ecx

        $sequence_2 = { 60 8b45fc b10b d3c0 }
            // n = 4, score = 1100
            //   60                   | pushal              
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   b10b                 | mov                 cl, 0xb
            //   d3c0                 | rol                 eax, cl

        $sequence_3 = { 888415f0feffff eb84 c785e8feffff00000000 c745fc00000000 }
            // n = 4, score = 800
            //   888415f0feffff       | mov                 byte ptr [ebp + edx - 0x110], al
            //   eb84                 | jmp                 0xffffff86
            //   c785e8feffff00000000     | mov    dword ptr [ebp - 0x118], 0
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0

        $sequence_4 = { 0f83a6000000 8b45f4 83c001 25ff000000 8945f4 8b4df4 0fbe940df0feffff }
            // n = 7, score = 800
            //   0f83a6000000         | jae                 0xac
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   83c001               | add                 eax, 1
            //   25ff000000           | and                 eax, 0xff
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   0fbe940df0feffff     | movsx               edx, byte ptr [ebp + ecx - 0x110]

        $sequence_5 = { 81ec18010000 6800010000 6a00 8d85f0feffff 50 }
            // n = 5, score = 800
            //   81ec18010000         | sub                 esp, 0x118
            //   6800010000           | push                0x100
            //   6a00                 | push                0
            //   8d85f0feffff         | lea                 eax, [ebp - 0x110]
            //   50                   | push                eax

        $sequence_6 = { 83c101 894dfc 8b55fc 3b5510 0f83a6000000 }
            // n = 5, score = 800
            //   83c101               | add                 ecx, 1
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   3b5510               | cmp                 edx, dword ptr [ebp + 0x10]
            //   0f83a6000000         | jae                 0xac

        $sequence_7 = { 8d85f0feffff 2bd0 8b4df8 83c101 894df8 81faff000000 }
            // n = 6, score = 800
            //   8d85f0feffff         | lea                 eax, [ebp - 0x110]
            //   2bd0                 | sub                 edx, eax
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   83c101               | add                 ecx, 1
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   81faff000000         | cmp                 edx, 0xff

        $sequence_8 = { 3bc6 7431 56 8d55f4 52 }
            // n = 5, score = 500
            //   3bc6                 | cmp                 eax, esi
            //   7431                 | je                  0x33
            //   56                   | push                esi
            //   8d55f4               | lea                 edx, [ebp - 0xc]
            //   52                   | push                edx

        $sequence_9 = { 52 8d8588fbffff 50 e8???????? }
            // n = 4, score = 500
            //   52                   | push                edx
            //   8d8588fbffff         | lea                 eax, [ebp - 0x478]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_10 = { 895df8 ff15???????? 85c0 756a 6a10 }
            // n = 5, score = 500
            //   895df8               | mov                 dword ptr [ebp - 8], ebx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   756a                 | jne                 0x6c
            //   6a10                 | push                0x10

        $sequence_11 = { 56 e8???????? 56 c6456f01 }
            // n = 4, score = 500
            //   56                   | push                esi
            //   e8????????           |                     
            //   56                   | push                esi
            //   c6456f01             | mov                 byte ptr [ebp + 0x6f], 1

        $sequence_12 = { 834de8ff 85c0 7906 0fb7d0 }
            // n = 4, score = 500
            //   834de8ff             | or                  dword ptr [ebp - 0x18], 0xffffffff
            //   85c0                 | test                eax, eax
            //   7906                 | jns                 8
            //   0fb7d0               | movzx               edx, ax

        $sequence_13 = { 85ff 0f8495000000 56 ff7508 57 }
            // n = 5, score = 500
            //   85ff                 | test                edi, edi
            //   0f8495000000         | je                  0x9b
            //   56                   | push                esi
            //   ff7508               | push                dword ptr [ebp + 8]
            //   57                   | push                edi

        $sequence_14 = { 6a04 8d55f8 52 8b856cfdffff }
            // n = 4, score = 200
            //   6a04                 | push                4
            //   8d55f8               | lea                 edx, [ebp - 8]
            //   52                   | push                edx
            //   8b856cfdffff         | mov                 eax, dword ptr [ebp - 0x294]

        $sequence_15 = { ebbd 8b4510 8b4dd8 8908 }
            // n = 4, score = 200
            //   ebbd                 | jmp                 0xffffffbf
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8b4dd8               | mov                 ecx, dword ptr [ebp - 0x28]
            //   8908                 | mov                 dword ptr [eax], ecx

        $sequence_16 = { 83ec08 837d0c00 740e 68???????? 8b450c 50 e8???????? }
            // n = 7, score = 200
            //   83ec08               | sub                 esp, 8
            //   837d0c00             | cmp                 dword ptr [ebp + 0xc], 0
            //   740e                 | je                  0x10
            //   68????????           |                     
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_17 = { 8bec 83ec1c c745f000000000 8b4508 33c9 3b4510 }
            // n = 6, score = 200
            //   8bec                 | mov                 ebp, esp
            //   83ec1c               | sub                 esp, 0x1c
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   33c9                 | xor                 ecx, ecx
            //   3b4510               | cmp                 eax, dword ptr [ebp + 0x10]

        $sequence_18 = { 8845ff 8a4dff 51 8b5508 52 e8???????? 894508 }
            // n = 7, score = 200
            //   8845ff               | mov                 byte ptr [ebp - 1], al
            //   8a4dff               | mov                 cl, byte ptr [ebp - 1]
            //   51                   | push                ecx
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   52                   | push                edx
            //   e8????????           |                     
            //   894508               | mov                 dword ptr [ebp + 8], eax

        $sequence_19 = { 7412 0fbe4d08 83f92f 7409 0fbe5508 83fa3d 7507 }
            // n = 7, score = 200
            //   7412                 | je                  0x14
            //   0fbe4d08             | movsx               ecx, byte ptr [ebp + 8]
            //   83f92f               | cmp                 ecx, 0x2f
            //   7409                 | je                  0xb
            //   0fbe5508             | movsx               edx, byte ptr [ebp + 8]
            //   83fa3d               | cmp                 edx, 0x3d
            //   7507                 | jne                 9

        $sequence_20 = { 6a00 6a00 6880400700 8b4df8 51 ff15???????? }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6880400700           | push                0x74080
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   51                   | push                ecx
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 163840
}