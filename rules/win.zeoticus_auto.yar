rule win_zeoticus_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.zeoticus."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zeoticus"
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
        $sequence_0 = { 68???????? 50 ff15???????? 8d9c2424080000 83c40c 8d4b02 668b03 }
            // n = 7, score = 100
            //   68????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d9c2424080000       | lea                 ebx, [esp + 0x824]
            //   83c40c               | add                 esp, 0xc
            //   8d4b02               | lea                 ecx, [ebx + 2]
            //   668b03               | mov                 ax, word ptr [ebx]

        $sequence_1 = { c1f919 01742418 89b4247c010000 13c1 8b8c24a4000000 89842458010000 8b842498000000 }
            // n = 7, score = 100
            //   c1f919               | sar                 ecx, 0x19
            //   01742418             | add                 dword ptr [esp + 0x18], esi
            //   89b4247c010000       | mov                 dword ptr [esp + 0x17c], esi
            //   13c1                 | adc                 eax, ecx
            //   8b8c24a4000000       | mov                 ecx, dword ptr [esp + 0xa4]
            //   89842458010000       | mov                 dword ptr [esp + 0x158], eax
            //   8b842498000000       | mov                 eax, dword ptr [esp + 0x98]

        $sequence_2 = { 8bf9 68cb305048 6a0f ba???????? b996321227 e8???????? 83c408 }
            // n = 7, score = 100
            //   8bf9                 | mov                 edi, ecx
            //   68cb305048           | push                0x485030cb
            //   6a0f                 | push                0xf
            //   ba????????           |                     
            //   b996321227           | mov                 ecx, 0x27123296
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_3 = { 8b94249c000000 c1e01a 2bd0 8b8424a8000000 8994249c000000 89542478 8b9424a0000000 }
            // n = 7, score = 100
            //   8b94249c000000       | mov                 edx, dword ptr [esp + 0x9c]
            //   c1e01a               | shl                 eax, 0x1a
            //   2bd0                 | sub                 edx, eax
            //   8b8424a8000000       | mov                 eax, dword ptr [esp + 0xa8]
            //   8994249c000000       | mov                 dword ptr [esp + 0x9c], edx
            //   89542478             | mov                 dword ptr [esp + 0x78], edx
            //   8b9424a0000000       | mov                 edx, dword ptr [esp + 0xa0]

        $sequence_4 = { 8345f410 660fefc4 660f62d9 660f6af1 0f28cb 0f1106 }
            // n = 6, score = 100
            //   8345f410             | add                 dword ptr [ebp - 0xc], 0x10
            //   660fefc4             | pxor                xmm0, xmm4
            //   660f62d9             | punpckldq           xmm3, xmm1
            //   660f6af1             | punpckhdq           xmm6, xmm1
            //   0f28cb               | movaps              xmm1, xmm3
            //   0f1106               | movups              xmmword ptr [esi], xmm0

        $sequence_5 = { c705????????00000000 c705????????00000000 e8???????? 83c408 a3???????? ffd0 a1???????? }
            // n = 7, score = 100
            //   c705????????00000000     |     
            //   c705????????00000000     |     
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   a3????????           |                     
            //   ffd0                 | call                eax
            //   a1????????           |                     

        $sequence_6 = { 0f29442440 c744245844000000 c784248400000044000000 85ff 751d 8b4c241c 8d8424f0140000 }
            // n = 7, score = 100
            //   0f29442440           | movaps              xmmword ptr [esp + 0x40], xmm0
            //   c744245844000000     | mov                 dword ptr [esp + 0x58], 0x44
            //   c784248400000044000000     | mov    dword ptr [esp + 0x84], 0x44
            //   85ff                 | test                edi, edi
            //   751d                 | jne                 0x1f
            //   8b4c241c             | mov                 ecx, dword ptr [esp + 0x1c]
            //   8d8424f0140000       | lea                 eax, [esp + 0x14f0]

        $sequence_7 = { 83c408 a3???????? 8d8c2442110000 8d0c59 894c240c 51 8d8c2404010000 }
            // n = 7, score = 100
            //   83c408               | add                 esp, 8
            //   a3????????           |                     
            //   8d8c2442110000       | lea                 ecx, [esp + 0x1142]
            //   8d0c59               | lea                 ecx, [ecx + ebx*2]
            //   894c240c             | mov                 dword ptr [esp + 0xc], ecx
            //   51                   | push                ecx
            //   8d8c2404010000       | lea                 ecx, [esp + 0x104]

        $sequence_8 = { 7512 ff15???????? 83f850 7507 c7450001000000 57 e8???????? }
            // n = 7, score = 100
            //   7512                 | jne                 0x14
            //   ff15????????         |                     
            //   83f850               | cmp                 eax, 0x50
            //   7507                 | jne                 9
            //   c7450001000000       | mov                 dword ptr [ebp], 1
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_9 = { 8b4818 8945fc 894df4 8b413c 8b440878 03c1 8945f8 }
            // n = 7, score = 100
            //   8b4818               | mov                 ecx, dword ptr [eax + 0x18]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   8b413c               | mov                 eax, dword ptr [ecx + 0x3c]
            //   8b440878             | mov                 eax, dword ptr [eax + ecx + 0x78]
            //   03c1                 | add                 eax, ecx
            //   8945f8               | mov                 dword ptr [ebp - 8], eax

    condition:
        7 of them and filesize < 468992
}