rule win_purplewave_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.purplewave."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.purplewave"
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
        $sequence_0 = { e8???????? 8d4da4 c645fc12 e8???????? 84db 0f84ca020000 6a40 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   8d4da4               | lea                 ecx, [ebp - 0x5c]
            //   c645fc12             | mov                 byte ptr [ebp - 4], 0x12
            //   e8????????           |                     
            //   84db                 | test                bl, bl
            //   0f84ca020000         | je                  0x2d0
            //   6a40                 | push                0x40

        $sequence_1 = { 0f8415000000 81a53cffffffffbfffff 8d8da8feffff e9???????? c3 8d8d60feffff e9???????? }
            // n = 7, score = 400
            //   0f8415000000         | je                  0x1b
            //   81a53cffffffffbfffff     | and    dword ptr [ebp - 0xc4], 0xffffbfff
            //   8d8da8feffff         | lea                 ecx, [ebp - 0x158]
            //   e9????????           |                     
            //   c3                   | ret                 
            //   8d8d60feffff         | lea                 ecx, [ebp - 0x1a0]
            //   e9????????           |                     

        $sequence_2 = { 8d8c2468010000 e8???????? 6a0d e8???????? 59 56 8bd0 }
            // n = 7, score = 400
            //   8d8c2468010000       | lea                 ecx, [esp + 0x168]
            //   e8????????           |                     
            //   6a0d                 | push                0xd
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   56                   | push                esi
            //   8bd0                 | mov                 edx, eax

        $sequence_3 = { 6bc838 57 8b0495201e4900 8a440828 a848 757b 84c0 }
            // n = 7, score = 400
            //   6bc838               | imul                ecx, eax, 0x38
            //   57                   | push                edi
            //   8b0495201e4900       | mov                 eax, dword ptr [edx*4 + 0x491e20]
            //   8a440828             | mov                 al, byte ptr [eax + ecx + 0x28]
            //   a848                 | test                al, 0x48
            //   757b                 | jne                 0x7d
            //   84c0                 | test                al, al

        $sequence_4 = { 8d4dbc e8???????? 8d4dd4 e8???????? 8bc3 e8???????? c20c00 }
            // n = 7, score = 400
            //   8d4dbc               | lea                 ecx, [ebp - 0x44]
            //   e8????????           |                     
            //   8d4dd4               | lea                 ecx, [ebp - 0x2c]
            //   e8????????           |                     
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     
            //   c20c00               | ret                 0xc

        $sequence_5 = { b8???????? e8???????? 8bf9 8db78c000000 8bce e8???????? 84c0 }
            // n = 7, score = 400
            //   b8????????           |                     
            //   e8????????           |                     
            //   8bf9                 | mov                 edi, ecx
            //   8db78c000000         | lea                 esi, [edi + 0x8c]
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   84c0                 | test                al, al

        $sequence_6 = { 53 50 e8???????? 83c40c 8d8db8feffff e8???????? 8d95b8feffff }
            // n = 7, score = 400
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d8db8feffff         | lea                 ecx, [ebp - 0x148]
            //   e8????????           |                     
            //   8d95b8feffff         | lea                 edx, [ebp - 0x148]

        $sequence_7 = { 53 68???????? 50 ff5110 ff758c ffd6 50 }
            // n = 7, score = 400
            //   53                   | push                ebx
            //   68????????           |                     
            //   50                   | push                eax
            //   ff5110               | call                dword ptr [ecx + 0x10]
            //   ff758c               | push                dword ptr [ebp - 0x74]
            //   ffd6                 | call                esi
            //   50                   | push                eax

        $sequence_8 = { 0f85d3000000 8d45e8 50 8b06 8b08 83c128 }
            // n = 6, score = 400
            //   0f85d3000000         | jne                 0xd9
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   50                   | push                eax
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   83c128               | add                 ecx, 0x28

        $sequence_9 = { 84c0 750e 8d45d8 50 8d4e6c e8???????? eb49 }
            // n = 7, score = 400
            //   84c0                 | test                al, al
            //   750e                 | jne                 0x10
            //   8d45d8               | lea                 eax, [ebp - 0x28]
            //   50                   | push                eax
            //   8d4e6c               | lea                 ecx, [esi + 0x6c]
            //   e8????????           |                     
            //   eb49                 | jmp                 0x4b

    condition:
        7 of them and filesize < 1400832
}