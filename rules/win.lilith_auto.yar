rule win_lilith_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.lilith."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lilith"
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
        $sequence_0 = { 6bc030 03048da84b4300 50 ff15???????? }
            // n = 4, score = 200
            //   6bc030               | imul                eax, eax, 0x30
            //   03048da84b4300       | add                 eax, dword ptr [ecx*4 + 0x434ba8]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_1 = { eb7c c745e0c8874200 ebbb d9e8 8b4510 dd18 e9???????? }
            // n = 7, score = 200
            //   eb7c                 | jmp                 0x7e
            //   c745e0c8874200       | mov                 dword ptr [ebp - 0x20], 0x4287c8
            //   ebbb                 | jmp                 0xffffffbd
            //   d9e8                 | fld1                
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   dd18                 | fstp                qword ptr [eax]
            //   e9????????           |                     

        $sequence_2 = { ff15???????? 83f8ff 740f 03f0 3bf7 7cdc }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   83f8ff               | cmp                 eax, -1
            //   740f                 | je                  0x11
            //   03f0                 | add                 esi, eax
            //   3bf7                 | cmp                 esi, edi
            //   7cdc                 | jl                  0xffffffde

        $sequence_3 = { 83c102 51 53 e8???????? 83c40c 6a00 6a00 }
            // n = 7, score = 200
            //   83c102               | add                 ecx, 2
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_4 = { c745fc00000000 c746140f000000 c7461000000000 837e1410 89b558feffff 7204 8b06 }
            // n = 7, score = 200
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   c746140f000000       | mov                 dword ptr [esi + 0x14], 0xf
            //   c7461000000000       | mov                 dword ptr [esi + 0x10], 0
            //   837e1410             | cmp                 dword ptr [esi + 0x14], 0x10
            //   89b558feffff         | mov                 dword ptr [ebp - 0x1a8], esi
            //   7204                 | jb                  6
            //   8b06                 | mov                 eax, dword ptr [esi]

        $sequence_5 = { 7408 40 83f81d 7cf1 eb07 8b0cc5e4864200 894de4 }
            // n = 7, score = 200
            //   7408                 | je                  0xa
            //   40                   | inc                 eax
            //   83f81d               | cmp                 eax, 0x1d
            //   7cf1                 | jl                  0xfffffff3
            //   eb07                 | jmp                 9
            //   8b0cc5e4864200       | mov                 ecx, dword ptr [eax*8 + 0x4286e4]
            //   894de4               | mov                 dword ptr [ebp - 0x1c], ecx

        $sequence_6 = { 6a0f c743140f000000 8bcb c7431000000000 }
            // n = 4, score = 200
            //   6a0f                 | push                0xf
            //   c743140f000000       | mov                 dword ptr [ebx + 0x14], 0xf
            //   8bcb                 | mov                 ecx, ebx
            //   c7431000000000       | mov                 dword ptr [ebx + 0x10], 0

        $sequence_7 = { 83c408 8d4dc0 e8???????? 8d4da8 e8???????? }
            // n = 5, score = 200
            //   83c408               | add                 esp, 8
            //   8d4dc0               | lea                 ecx, dword ptr [ebp - 0x40]
            //   e8????????           |                     
            //   8d4da8               | lea                 ecx, dword ptr [ebp - 0x58]
            //   e8????????           |                     

        $sequence_8 = { 50 e8???????? 83c410 ebe6 8b45e4 8b0c85a84b4300 8b45e8 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   ebe6                 | jmp                 0xffffffe8
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   8b0c85a84b4300       | mov                 ecx, dword ptr [eax*4 + 0x434ba8]
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]

        $sequence_9 = { 6a00 68???????? c60000 e8???????? 8d4dd4 e8???????? }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   68????????           |                     
            //   c60000               | mov                 byte ptr [eax], 0
            //   e8????????           |                     
            //   8d4dd4               | lea                 ecx, dword ptr [ebp - 0x2c]
            //   e8????????           |                     

    condition:
        7 of them and filesize < 499712
}