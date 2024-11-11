rule win_atharvan_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.atharvan."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.atharvan"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
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
        $sequence_0 = { 488d4c2460 ff15???????? 0f57c0 488d9540020000 33c0 4533c9 48894598 }
            // n = 7, score = 100
            //   488d4c2460           | dec                 eax
            //   ff15????????         |                     
            //   0f57c0               | shl                 esi, 2
            //   488d9540020000       | movzx               eax, word ptr [ecx + edi*4 + 0x1a990]
            //   33c0                 | dec                 eax
            //   4533c9               | lea                 edx, [ecx + 0x1a080]
            //   48894598             | mov                 dword ptr [ebp + 0x6c0], eax

        $sequence_1 = { 4883c004 413bd0 7cf0 8bcf ff15???????? e9???????? }
            // n = 6, score = 100
            //   4883c004             | mov                 dword ptr [ebp + 0x10], esi
            //   413bd0               | dec                 esp
            //   7cf0                 | lea                 ecx, [ebp - 0x60]
            //   8bcf                 | mov                 dword ptr [esp + 0x20], eax
            //   ff15????????         |                     
            //   e9????????           |                     

        $sequence_2 = { 488945f0 488d4588 4889442448 488d45a0 4889442440 }
            // n = 5, score = 100
            //   488945f0             | mov                 dword ptr [ebp - 0x20], 0x84dfc2e0
            //   488d4588             | mov                 dword ptr [ebp - 0x1c], 0x859c989e
            //   4889442448           | mov                 dword ptr [ebp - 0x18], 0x838b9d98
            //   488d45a0             | mov                 dword ptr [ebp - 0x20], 0x84dfc2e0
            //   4889442440           | mov                 dword ptr [ebp - 0x1c], 0x859c989e

        $sequence_3 = { 0f8403010000 488d050eea0000 4a8b04e8 42385cf838 0f8ded000000 e8???????? 488b8890000000 }
            // n = 7, score = 100
            //   0f8403010000         | mov                 ebx, edx
            //   488d050eea0000       | dec                 ecx
            //   4a8b04e8             | mov                 ebp, eax
            //   42385cf838           | xor                 ecx, ecx
            //   0f8ded000000         | dec                 esp
            //   e8????????           |                     
            //   488b8890000000       | lea                 eax, [0xffff60c9]

        $sequence_4 = { 4883ec20 84c9 752f 488d1d3f380100 488b0b 4885c9 7410 }
            // n = 7, score = 100
            //   4883ec20             | dec                 eax
            //   84c9                 | lea                 ecx, [ebp - 0x50]
            //   752f                 | dec                 eax
            //   488d1d3f380100       | mov                 ebx, dword ptr [esp + 0x98]
            //   488b0b               | mov                 dword ptr [esi + 0x228], eax
            //   4885c9               | dec                 ecx
            //   7410                 | mov                 ecx, esp

        $sequence_5 = { 0fb602 84c0 75f1 488d0df2360200 ff15???????? 488bd8 }
            // n = 6, score = 100
            //   0fb602               | dec                 eax
            //   84c0                 | shl                 esi, 2
            //   75f1                 | dec                 eax
            //   488d0df2360200       | lea                 ecx, [ebp + 0x324]
            //   ff15????????         |                     
            //   488bd8               | mov                 dword ptr [ebp + 0x320], eax

        $sequence_6 = { 0fb601 84c0 75f1 488d542430 488d4d60 e8???????? 488bd8 }
            // n = 7, score = 100
            //   0fb601               | lea                 eax, [0x7be0]
            //   84c0                 | dec                 eax
            //   75f1                 | cmp                 ecx, eax
            //   488d542430           | je                  0x1a4f
            //   488d4d60             | or                  eax, 0xffffffff
            //   e8????????           |                     
            //   488bd8               | lock xadd           dword ptr [ecx + 0x15c], eax

        $sequence_7 = { 488bce e8???????? eb1a 0fb6d1 c7862002000001000000 488bce 4c8d442451 }
            // n = 7, score = 100
            //   488bce               | dec                 ebp
            //   e8????????           |                     
            //   eb1a                 | mov                 esi, ecx
            //   0fb6d1               | mov                 dword ptr [ebp - 0x7f], 0xcf8e96
            //   c7862002000001000000     | mov    dword ptr [esp + 0x59], 0xd9cac3df
            //   488bce               | mov                 dword ptr [esp + 0x5d], 0xc5cadd
            //   4c8d442451           | dec                 eax

        $sequence_8 = { 488d4da0 41b804010000 e8???????? 4d8bc4 488d8db0000000 ba04010000 }
            // n = 6, score = 100
            //   488d4da0             | lea                 ecx, [ecx + 1]
            //   41b804010000         | mov                 dword ptr [esp + 0x5d], 0xcec7c2cd
            //   e8????????           |                     
            //   4d8bc4               | mov                 dword ptr [esp + 0x61], 0xa1a68a
            //   488d8db0000000       | nop                 word ptr [eax + eax]
            //   ba04010000           | xor                 al, 0xab

        $sequence_9 = { 488945ff 488d05a0b60000 4889450f 488d05a5b60000 48895507 }
            // n = 5, score = 100
            //   488945ff             | mov                 dword ptr [ebp - 0x18], 0x838b9d98
            //   488d05a0b60000       | mov                 dword ptr [ebp - 0x14], 0xe6ffe3e0
            //   4889450f             | mov                 dword ptr [ebp - 0x10], 0xc78b87e7
            //   488d05a5b60000       | mov                 dword ptr [ebp - 0xc], 0x8bcec0c2
            //   48895507             | mov                 dword ptr [ebp - 0x17], 0xffea86e2

    condition:
        7 of them and filesize < 348160
}