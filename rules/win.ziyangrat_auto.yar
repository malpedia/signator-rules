rule win_ziyangrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.ziyangrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ziyangrat"
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
        $sequence_0 = { 83c9ff f2ae f7d1 49 51 8d4c2468 51 }
            // n = 7, score = 200
            //   83c9ff               | or                  ecx, 0xffffffff
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx
            //   51                   | push                ecx
            //   8d4c2468             | lea                 ecx, [esp + 0x68]
            //   51                   | push                ecx

        $sequence_1 = { 4d 81fddc0f0000 7dee 68ee0f0000 e8???????? 83c404 eb04 }
            // n = 7, score = 200
            //   4d                   | dec                 ebp
            //   81fddc0f0000         | cmp                 ebp, 0xfdc
            //   7dee                 | jge                 0xfffffff0
            //   68ee0f0000           | push                0xfee
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   eb04                 | jmp                 6

        $sequence_2 = { 396c242c 0f8537030000 e9???????? 8b35???????? 8d442414 8a10 }
            // n = 6, score = 200
            //   396c242c             | cmp                 dword ptr [esp + 0x2c], ebp
            //   0f8537030000         | jne                 0x33d
            //   e9????????           |                     
            //   8b35????????         |                     
            //   8d442414             | lea                 eax, [esp + 0x14]
            //   8a10                 | mov                 dl, byte ptr [eax]

        $sequence_3 = { b90b000000 be???????? 8d7c240c 33c0 f3a5 a4 8d7c240c }
            // n = 7, score = 200
            //   b90b000000           | mov                 ecx, 0xb
            //   be????????           |                     
            //   8d7c240c             | lea                 edi, [esp + 0xc]
            //   33c0                 | xor                 eax, eax
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   a4                   | movsb               byte ptr es:[edi], byte ptr [esi]
            //   8d7c240c             | lea                 edi, [esp + 0xc]

        $sequence_4 = { 83c1ff 51 8d8548e6ffff 50 }
            // n = 4, score = 200
            //   83c1ff               | add                 ecx, -1
            //   51                   | push                ecx
            //   8d8548e6ffff         | lea                 eax, [ebp - 0x19b8]
            //   50                   | push                eax

        $sequence_5 = { 8b442420 3bd0 7f75 33c0 8a040a }
            // n = 5, score = 200
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   3bd0                 | cmp                 edx, eax
            //   7f75                 | jg                  0x77
            //   33c0                 | xor                 eax, eax
            //   8a040a               | mov                 al, byte ptr [edx + ecx]

        $sequence_6 = { 8b4c2410 56 50 51 e8???????? 68???????? 8d542420 }
            // n = 7, score = 200
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   56                   | push                esi
            //   50                   | push                eax
            //   51                   | push                ecx
            //   e8????????           |                     
            //   68????????           |                     
            //   8d542420             | lea                 edx, [esp + 0x20]

        $sequence_7 = { 8b54241c 68???????? 56 8d842438030000 52 }
            // n = 5, score = 200
            //   8b54241c             | mov                 edx, dword ptr [esp + 0x1c]
            //   68????????           |                     
            //   56                   | push                esi
            //   8d842438030000       | lea                 eax, [esp + 0x338]
            //   52                   | push                edx

        $sequence_8 = { e8???????? 68e8030000 ff15???????? 33c0 83c420 c3 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   68e8030000           | push                0x3e8
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax
            //   83c420               | add                 esp, 0x20
            //   c3                   | ret                 

        $sequence_9 = { 833900 7416 8b4c2448 8b742414 8a540428 88140e 46 }
            // n = 7, score = 200
            //   833900               | cmp                 dword ptr [ecx], 0
            //   7416                 | je                  0x18
            //   8b4c2448             | mov                 ecx, dword ptr [esp + 0x48]
            //   8b742414             | mov                 esi, dword ptr [esp + 0x14]
            //   8a540428             | mov                 dl, byte ptr [esp + eax + 0x28]
            //   88140e               | mov                 byte ptr [esi + ecx], dl
            //   46                   | inc                 esi

    condition:
        7 of them and filesize < 188416
}