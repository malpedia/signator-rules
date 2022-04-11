rule win_dnespy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.dnespy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dnespy"
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
        $sequence_0 = { e8???????? c7850ccfffff00000000 c78510cfffff00000000 0f1000 0f1185fcceffff f30f7e4010 660fd6850ccfffff }
            // n = 7, score = 200
            //   e8????????           |                     
            //   c7850ccfffff00000000     | mov    dword ptr [ebp - 0x30f4], 0
            //   c78510cfffff00000000     | mov    dword ptr [ebp - 0x30f0], 0
            //   0f1000               | movups              xmm0, xmmword ptr [eax]
            //   0f1185fcceffff       | movups              xmmword ptr [ebp - 0x3104], xmm0
            //   f30f7e4010           | movq                xmm0, qword ptr [eax + 0x10]
            //   660fd6850ccfffff     | movq                qword ptr [ebp - 0x30f4], xmm0

        $sequence_1 = { 7606 ff15???????? 52 51 e8???????? 83c408 83bde4fbffff10 }
            // n = 7, score = 200
            //   7606                 | jbe                 8
            //   ff15????????         |                     
            //   52                   | push                edx
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   83bde4fbffff10       | cmp                 dword ptr [ebp - 0x41c], 0x10

        $sequence_2 = { 75f5 83ea01 75eb 5f 5e 5d 5b }
            // n = 7, score = 200
            //   75f5                 | jne                 0xfffffff7
            //   83ea01               | sub                 edx, 1
            //   75eb                 | jne                 0xffffffed
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx

        $sequence_3 = { c7460489674523 c7460890785634 8a4d00 84c9 745b 53 57 }
            // n = 7, score = 200
            //   c7460489674523       | mov                 dword ptr [esi + 4], 0x23456789
            //   c7460890785634       | mov                 dword ptr [esi + 8], 0x34567890
            //   8a4d00               | mov                 cl, byte ptr [ebp]
            //   84c9                 | test                cl, cl
            //   745b                 | je                  0x5d
            //   53                   | push                ebx
            //   57                   | push                edi

        $sequence_4 = { 884592 8b8564ffffff 042b 3475 884593 8b8564ffffff 042c }
            // n = 7, score = 200
            //   884592               | mov                 byte ptr [ebp - 0x6e], al
            //   8b8564ffffff         | mov                 eax, dword ptr [ebp - 0x9c]
            //   042b                 | add                 al, 0x2b
            //   3475                 | xor                 al, 0x75
            //   884593               | mov                 byte ptr [ebp - 0x6d], al
            //   8b8564ffffff         | mov                 eax, dword ptr [ebp - 0x9c]
            //   042c                 | add                 al, 0x2c

        $sequence_5 = { 8a8998c54400 8bb0bc160000 0fb6f9 8b4c2430 0fb714b9 0fb75cb902 8bca }
            // n = 7, score = 200
            //   8a8998c54400         | mov                 cl, byte ptr [ecx + 0x44c598]
            //   8bb0bc160000         | mov                 esi, dword ptr [eax + 0x16bc]
            //   0fb6f9               | movzx               edi, cl
            //   8b4c2430             | mov                 ecx, dword ptr [esp + 0x30]
            //   0fb714b9             | movzx               edx, word ptr [ecx + edi*4]
            //   0fb75cb902           | movzx               ebx, word ptr [ecx + edi*4 + 2]
            //   8bca                 | mov                 ecx, edx

        $sequence_6 = { 0f8554010000 8d5e08 8b4720 55 68c4160000 6a01 ff7728 }
            // n = 7, score = 200
            //   0f8554010000         | jne                 0x15a
            //   8d5e08               | lea                 ebx, dword ptr [esi + 8]
            //   8b4720               | mov                 eax, dword ptr [edi + 0x20]
            //   55                   | push                ebp
            //   68c4160000           | push                0x16c4
            //   6a01                 | push                1
            //   ff7728               | push                dword ptr [edi + 0x28]

        $sequence_7 = { 668b442418 66d3e0 660bc3 0fb7c0 57 668987b8160000 e8???????? }
            // n = 7, score = 200
            //   668b442418           | mov                 ax, word ptr [esp + 0x18]
            //   66d3e0               | shl                 ax, cl
            //   660bc3               | or                  ax, bx
            //   0fb7c0               | movzx               eax, ax
            //   57                   | push                edi
            //   668987b8160000       | mov                 word ptr [edi + 0x16b8], ax
            //   e8????????           |                     

        $sequence_8 = { 85c0 750c 56 ff15???????? 83ceff eb88 837b1c10 }
            // n = 7, score = 200
            //   85c0                 | test                eax, eax
            //   750c                 | jne                 0xe
            //   56                   | push                esi
            //   ff15????????         |                     
            //   83ceff               | or                  esi, 0xffffffff
            //   eb88                 | jmp                 0xffffff8a
            //   837b1c10             | cmp                 dword ptr [ebx + 0x1c], 0x10

        $sequence_9 = { 8a19 8b8dec000000 8b95f8000000 0fbec3 33c1 c1e908 0fb6c0 }
            // n = 7, score = 200
            //   8a19                 | mov                 bl, byte ptr [ecx]
            //   8b8dec000000         | mov                 ecx, dword ptr [ebp + 0xec]
            //   8b95f8000000         | mov                 edx, dword ptr [ebp + 0xf8]
            //   0fbec3               | movsx               eax, bl
            //   33c1                 | xor                 eax, ecx
            //   c1e908               | shr                 ecx, 8
            //   0fb6c0               | movzx               eax, al

    condition:
        7 of them and filesize < 794624
}