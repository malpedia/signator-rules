rule win_turla_rpc_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.turla_rpc."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.turla_rpc"
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
        $sequence_0 = { 660f6f05???????? f30f7f8580010000 660f6f05???????? 66c785ec0000000255 }
            // n = 4, score = 200
            //   660f6f05????????     |                     
            //   f30f7f8580010000     | movdqu              xmmword ptr [ebp + 0x180], xmm0
            //   660f6f05????????     |                     
            //   66c785ec0000000255     | mov    word ptr [ebp + 0xec], 0x5502

        $sequence_1 = { c7854001000030163930 c78544010000343b2025 c6854801000055 c78560010000013c3830 c785640100003a202155 c785a8010000271c3367 }
            // n = 6, score = 200
            //   c7854001000030163930     | mov    dword ptr [ebp + 0x140], 0x30391630
            //   c78544010000343b2025     | mov    dword ptr [ebp + 0x144], 0x25203b34
            //   c6854801000055       | mov                 byte ptr [ebp + 0x148], 0x55
            //   c78560010000013c3830     | mov    dword ptr [ebp + 0x160], 0x30383c01
            //   c785640100003a202155     | mov    dword ptr [ebp + 0x164], 0x5521203a
            //   c785a8010000271c3367     | mov    dword ptr [ebp + 0x1a8], 0x67331c27

        $sequence_2 = { 4885c0 74e7 4883c440 5b c3 488d053bda0000 488d542458 }
            // n = 7, score = 200
            //   4885c0               | mov                 dword ptr [ebp + 0xb4], 0x10212634
            //   74e7                 | movdqu              xmmword ptr [ebp + 0x1c8], xmm0
            //   4883c440             | movdqu              xmmword ptr [ebp + 0x198], xmm1
            //   5b                   | dec                 eax
            //   c3                   | test                eax, eax
            //   488d053bda0000       | je                  0xffffffe9
            //   488d542458           | dec                 eax

        $sequence_3 = { 4885c0 744e 4c8b4708 488b17 }
            // n = 4, score = 200
            //   4885c0               | dec                 eax
            //   744e                 | test                eax, eax
            //   4c8b4708             | je                  0x50
            //   488b17               | dec                 esp

        $sequence_4 = { c785b400000034262110 f30f7f85c8010000 660f6f05???????? f30f7f8d98010000 }
            // n = 4, score = 200
            //   c785b400000034262110     | mov    eax, dword ptr [edi + 8]
            //   f30f7f85c8010000     | dec                 eax
            //   660f6f05????????     |                     
            //   f30f7f8d98010000     | mov                 edx, dword ptr [edi]

        $sequence_5 = { c7857801000026302410 66c7857c0100002502 c6857e01000055 c7452038262336 }
            // n = 4, score = 200
            //   c7857801000026302410     | dec    eax
            //   66c7857c0100002502     | lea    edx, [esp + 0x58]
            //   c6857e01000055       | dec                 eax
            //   c7452038262336       | test                eax, eax

        $sequence_6 = { c745b06970746f c745b472536163 66c745b86c00 ff15???????? }
            // n = 4, score = 200
            //   c745b06970746f       | mov                 ecx, ebx
            //   c745b472536163       | mov                 dword ptr [ebp + 0x178], 0x10243026
            //   66c745b86c00         | mov                 word ptr [ebp + 0x17c], 0x225
            //   ff15????????         |                     

        $sequence_7 = { 66c74424443e55 c744243833213039 66c744243c3955 c745803322273c }
            // n = 4, score = 200
            //   66c74424443e55       | mov                 word ptr [esp + 0x44], 0x553e
            //   c744243833213039     | mov                 dword ptr [esp + 0x38], 0x39302133
            //   66c744243c3955       | mov                 word ptr [esp + 0x3c], 0x5539
            //   c745803322273c       | mov                 dword ptr [ebp - 0x80], 0x3c272233

        $sequence_8 = { 66c7442474303b c644247655 c744246022362636 66c74424643825 c644246655 c745902236263b c7459436342155 }
            // n = 7, score = 200
            //   66c7442474303b       | mov                 word ptr [esp + 0x74], 0x3b30
            //   c644247655           | mov                 byte ptr [esp + 0x76], 0x55
            //   c744246022362636     | mov                 dword ptr [esp + 0x60], 0x36263622
            //   66c74424643825       | mov                 word ptr [esp + 0x64], 0x2538
            //   c644246655           | mov                 byte ptr [esp + 0x66], 0x55
            //   c745902236263b       | mov                 dword ptr [ebp - 0x70], 0x3b263622
            //   c7459436342155       | mov                 dword ptr [ebp - 0x6c], 0x55213436

        $sequence_9 = { 895dfc 391cfd40730110 7518 53 68a00f0000 56 e8???????? }
            // n = 7, score = 100
            //   895dfc               | cmp                 ebx, 0x3fffffff
            //   391cfd40730110       | ja                  0x67
            //   7518                 | lea                 eax, [ebx*4]
            //   53                   | push                eax
            //   68a00f0000           | test                eax, eax
            //   56                   | jne                 0xcc
            //   e8????????           |                     

        $sequence_10 = { 81fbffffff3f 775f 8d049d00000000 50 e8???????? }
            // n = 5, score = 100
            //   81fbffffff3f         | mov                 dword ptr [eax], 0xc
            //   775f                 | mov                 eax, ecx
            //   8d049d00000000       | pop                 esi
            //   50                   | pop                 ebp
            //   e8????????           |                     

        $sequence_11 = { c745f464647265 66c745f87373 ff15???????? 8bf0 85f6 }
            // n = 5, score = 100
            //   c745f464647265       | jb                  0xfffffff7
            //   66c745f87373         | xor                 eax, eax
            //   ff15????????         |                     
            //   8bf0                 | lea                 ecx, [ecx]
            //   85f6                 | xor                 byte ptr [ebp + eax - 0xe8], 0x55

        $sequence_12 = { 8945f4 8b4514 40 c745ec6aea0010 894df8 8945fc 64a100000000 }
            // n = 7, score = 100
            //   8945f4               | mov                 byte ptr [ebp + 0x17e], 0x55
            //   8b4514               | mov                 dword ptr [ebp + 0x20], 0x36232638
            //   40                   | mov                 dword ptr [ebp - 0x64], 0x553b3025
            //   c745ec6aea0010       | mov                 dword ptr [esp + 0x78], 0x39393436
            //   894df8               | mov                 word ptr [esp + 0x7c], 0x363a
            //   8945fc               | mov                 byte ptr [esp + 0x7e], 0x55
            //   64a100000000         | mov                 dword ptr [ebp - 0x78], 0x3a393633

        $sequence_13 = { 72f5 33c0 8d4900 80b40518ffffff55 }
            // n = 4, score = 100
            //   72f5                 | mov                 word ptr [ebp - 0x74], 0x3026
            //   33c0                 | mov                 dword ptr [ebp - 0x50], 0x6f747069
            //   8d4900               | mov                 dword ptr [ebp - 0x4c], 0x63615372
            //   80b40518ffffff55     | mov                 word ptr [ebp - 0x48], 0x6c

        $sequence_14 = { 85c0 0f85c6000000 8d4588 8bd7 50 ffb504ffffff 8d8decfeffff }
            // n = 7, score = 100
            //   85c0                 | ret                 
            //   0f85c6000000         | push                ebx
            //   8d4588               | mov                 ebx, esp
            //   8bd7                 | mov                 dword ptr [ebp - 0xc], 0x65726464
            //   50                   | mov                 word ptr [ebp - 8], 0x7373
            //   ffb504ffffff         | mov                 esi, eax
            //   8d8decfeffff         | test                esi, esi

        $sequence_15 = { c7000c000000 8bc1 5e 5d c3 53 8bdc }
            // n = 7, score = 100
            //   c7000c000000         | mov                 dword ptr [ebp - 0xc], eax
            //   8bc1                 | mov                 eax, dword ptr [ebp + 0x14]
            //   5e                   | inc                 eax
            //   5d                   | mov                 dword ptr [ebp - 0x14], 0x1000ea6a
            //   c3                   | mov                 dword ptr [ebp - 8], ecx
            //   53                   | mov                 dword ptr [ebp - 4], eax
            //   8bdc                 | mov                 eax, dword ptr fs:[0]

    condition:
        7 of them and filesize < 311296
}