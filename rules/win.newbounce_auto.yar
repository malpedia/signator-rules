rule win_newbounce_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.newbounce."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.newbounce"
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
        $sequence_0 = { 83e00f 7e05 2bf0 83c610 }
            // n = 4, score = 300
            //   83e00f               | and                 eax, 0xf
            //   7e05                 | jle                 7
            //   2bf0                 | sub                 esi, eax
            //   83c610               | add                 esi, 0x10

        $sequence_1 = { 754d 488bcf e8???????? 8b8c24a0000000 }
            // n = 4, score = 200
            //   754d                 | jne                 0x4f
            //   488bcf               | dec                 eax
            //   e8????????           |                     
            //   8b8c24a0000000       | mov                 ecx, edi

        $sequence_2 = { 754e 8d563a 488d4c2470 e8???????? }
            // n = 4, score = 200
            //   754e                 | dec                 eax
            //   8d563a               | lea                 ecx, [esp + 0x30]
            //   488d4c2470           | xor                 edx, edx
            //   e8????????           |                     

        $sequence_3 = { 754e 488b08 488bd0 488b4110 488902 488b4110 40387829 }
            // n = 7, score = 200
            //   754e                 | jne                 0x4e
            //   488b08               | dec                 esp
            //   488bd0               | lea                 eax, [0x1366e]
            //   488b4110             | dec                 ecx
            //   488902               | mov                 edx, esi
            //   488b4110             | dec                 eax
            //   40387829             | mov                 ecx, ebp

        $sequence_4 = { 754e 488d1531650200 488bcb e8???????? }
            // n = 4, score = 200
            //   754e                 | jne                 0x50
            //   488d1531650200       | inc                 esp
            //   488bcb               | cmp                 byte ptr [edi + 1], ah
            //   e8????????           |                     

        $sequence_5 = { 754e 44386701 7548 4c8d056e360100 }
            // n = 4, score = 200
            //   754e                 | mov                 ecx, edi
            //   44386701             | mov                 ecx, dword ptr [esp + 0xa0]
            //   7548                 | imul                ecx, ecx, 0x3e8
            //   4c8d056e360100       | inc                 esi

        $sequence_6 = { 754f 8bcb ff15???????? 83c364 }
            // n = 4, score = 200
            //   754f                 | jne                 0x50
            //   8bcb                 | test                edi, edi
            //   ff15????????         |                     
            //   83c364               | je                  0x4e

        $sequence_7 = { 754e 85ff 744a 4c8d4c2460 }
            // n = 4, score = 200
            //   754e                 | mov                 dword ptr [edx], eax
            //   85ff                 | dec                 eax
            //   744a                 | mov                 eax, dword ptr [ecx + 0x10]
            //   4c8d4c2460           | inc                 eax

        $sequence_8 = { 81e6c0000000 0bd6 c1ea06 0b0c95b0876300 }
            // n = 4, score = 100
            //   81e6c0000000         | and                 edx, 0x3f
            //   0bd6                 | or                  ecx, dword ptr [edx*4 + 0x6386b0]
            //   c1ea06               | mov                 edx, ebp
            //   0b0c95b0876300       | shr                 edx, 1

        $sequence_9 = { 81e580010000 0bdd c1eb07 0b349db08b6300 }
            // n = 4, score = 100
            //   81e580010000         | mov                 ecx, ebx
            //   0bdd                 | add                 ebx, 0x64
            //   c1eb07               | cmp                 ebx, 0x44c
            //   0b349db08b6300       | jl                  0xfffffff5

        $sequence_10 = { 81e600000006 81e3001e0000 8bef 81e50000e001 0bf5 c1ee15 8b34b5b08d6300 }
            // n = 7, score = 100
            //   81e600000006         | shr                 edi, 0xd
            //   81e3001e0000         | or                  ecx, dword ptr [edi*4 + 0x6388b0]
            //   8bef                 | mov                 edi, esi
            //   81e50000e001         | and                 ebp, 0x1e000
            //   0bf5                 | or                  edi, ebp
            //   c1ee15               | shr                 edi, 0xd
            //   8b34b5b08d6300       | or                  ecx, dword ptr [edi*4 + 0x6388b0]

        $sequence_11 = { 81e500e00100 0bfd c1ef0d 0b0cbdb0886300 }
            // n = 4, score = 100
            //   81e500e00100         | lea                 ecx, [esp + 0x70]
            //   0bfd                 | dec                 eax
            //   c1ef0d               | mov                 edi, eax
            //   0b0cbdb0886300       | dec                 eax

        $sequence_12 = { 81e5ffffff0f 8bd7 83e23f 0b0c95b0866300 }
            // n = 4, score = 100
            //   81e5ffffff0f         | mov                 ecx, ebx
            //   8bd7                 | dec                 eax
            //   83e23f               | lea                 edx, [0x2d4bd]
            //   0b0c95b0866300       | dec                 eax

        $sequence_13 = { 81e500e00100 0bdd c1eb0d 0b149db0886300 8bd9 81e3c0000000 0bf3 }
            // n = 7, score = 100
            //   81e500e00100         | dec                 eax
            //   0bdd                 | lea                 ecx, [esp + 0x70]
            //   c1eb0d               | dec                 eax
            //   0b149db0886300       | mov                 edi, eax
            //   8bd9                 | jne                 0x50
            //   81e3c0000000         | lea                 edx, [esi + 0x3a]
            //   0bf3                 | dec                 eax

        $sequence_14 = { 81e600000600 c1e914 8b0c8db0896300 8954241c }
            // n = 4, score = 100
            //   81e600000600         | mov                 edi, esi
            //   c1e914               | and                 edi, 0xc0
            //   8b0c8db0896300       | and                 ebp, 0x1e000
            //   8954241c             | or                  edi, ebp

    condition:
        7 of them and filesize < 8637440
}