rule win_squirrelwaffle_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.squirrelwaffle."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.squirrelwaffle"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
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
        $sequence_0 = { ffd6 85c0 0f85d9000000 8b458c }
            // n = 4, score = 700
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   0f85d9000000         | jne                 0xdf
            //   8b458c               | mov                 eax, dword ptr [ebp - 0x74]

        $sequence_1 = { 0f431d???????? 8a00 85c9 7416 51 }
            // n = 5, score = 700
            //   0f431d????????       |                     
            //   8a00                 | mov                 al, byte ptr [eax]
            //   85c9                 | test                ecx, ecx
            //   7416                 | je                  0x18
            //   51                   | push                ecx

        $sequence_2 = { 83c40c 8b36 ba???????? 85f6 0f853cffffff 8b7d88 }
            // n = 6, score = 700
            //   83c40c               | add                 esp, 0xc
            //   8b36                 | mov                 esi, dword ptr [esi]
            //   ba????????           |                     
            //   85f6                 | test                esi, esi
            //   0f853cffffff         | jne                 0xffffff42
            //   8b7d88               | mov                 edi, dword ptr [ebp - 0x78]

        $sequence_3 = { 85c0 0f8453020000 8b4a14 48 8945f0 8bc2 }
            // n = 6, score = 700
            //   85c0                 | test                eax, eax
            //   0f8453020000         | je                  0x259
            //   8b4a14               | mov                 ecx, dword ptr [edx + 0x14]
            //   48                   | dec                 eax
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8bc2                 | mov                 eax, edx

        $sequence_4 = { 8b7310 2bc6 8975f8 57 3bc2 0f8214010000 8d0416 }
            // n = 7, score = 700
            //   8b7310               | mov                 esi, dword ptr [ebx + 0x10]
            //   2bc6                 | sub                 eax, esi
            //   8975f8               | mov                 dword ptr [ebp - 8], esi
            //   57                   | push                edi
            //   3bc2                 | cmp                 eax, edx
            //   0f8214010000         | jb                  0x11a
            //   8d0416               | lea                 eax, [esi + edx]

        $sequence_5 = { b803000000 0f438d10fefeff ba???????? 83fe03 }
            // n = 4, score = 700
            //   b803000000           | mov                 eax, 3
            //   0f438d10fefeff       | cmovae              ecx, dword ptr [ebp - 0x101f0]
            //   ba????????           |                     
            //   83fe03               | cmp                 esi, 3

        $sequence_6 = { 0f1185f8fdfeff f30f7e4710 660fd68508fefeff c7471000000000 c747140f000000 }
            // n = 5, score = 700
            //   0f1185f8fdfeff       | movups              xmmword ptr [ebp - 0x10208], xmm0
            //   f30f7e4710           | movq                xmm0, qword ptr [edi + 0x10]
            //   660fd68508fefeff     | movq                qword ptr [ebp - 0x101f8], xmm0
            //   c7471000000000       | mov                 dword ptr [edi + 0x10], 0
            //   c747140f000000       | mov                 dword ptr [edi + 0x14], 0xf

        $sequence_7 = { 8db5f8fbffff 8d34c6 837e1410 8bc6 7202 }
            // n = 5, score = 700
            //   8db5f8fbffff         | lea                 esi, [ebp - 0x408]
            //   8d34c6               | lea                 esi, [esi + eax*8]
            //   837e1410             | cmp                 dword ptr [esi + 0x14], 0x10
            //   8bc6                 | mov                 eax, esi
            //   7202                 | jb                  4

        $sequence_8 = { 897714 eb26 8b0d???????? 0f57c0 }
            // n = 4, score = 700
            //   897714               | mov                 dword ptr [edi + 0x14], esi
            //   eb26                 | jmp                 0x28
            //   8b0d????????         |                     
            //   0f57c0               | xorps               xmm0, xmm0

        $sequence_9 = { c645cc00 8d4dd8 ff75cc 6a08 }
            // n = 4, score = 700
            //   c645cc00             | mov                 byte ptr [ebp - 0x34], 0
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   ff75cc               | push                dword ptr [ebp - 0x34]
            //   6a08                 | push                8

    condition:
        7 of them and filesize < 147456
}