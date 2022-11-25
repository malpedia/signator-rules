rule win_redshawl_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.redshawl."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redshawl"
        malpedia_rule_date = "20221118"
        malpedia_hash = "e0702e2e6d1d00da65c8a29a4ebacd0a4c59e1af"
        malpedia_version = "20221125"
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
        $sequence_0 = { 48897c2418 4154 4883ec20 4c8d258c990000 33f6 33db 498bfc }
            // n = 7, score = 100
            //   48897c2418           | lea                 eax, [esp + 0x240]
            //   4154                 | dec                 eax
            //   4883ec20             | mov                 dword ptr [esp + 0x40], eax
            //   4c8d258c990000       | dec                 eax
            //   33f6                 | mov                 eax, dword ptr [esp + 0x78]
            //   33db                 | dec                 eax
            //   498bfc               | mov                 dword ptr [esp + 0x38], eax

        $sequence_1 = { c645dc00 c745e077747361 c745e470693332 c745e82e646c6c c645ec00 c745a077696e73 }
            // n = 6, score = 100
            //   c645dc00             | xor                 eax, eax
            //   c745e077747361       | dec                 eax
            //   c745e470693332       | lea                 edx, [0xbb3b]
            //   c745e82e646c6c       | inc                 ebp
            //   c645ec00             | lea                 ecx, [eax + 3]
            //   c745a077696e73       | dec                 ecx

        $sequence_2 = { 752f 488d0d2a9b0000 e8???????? ff15???????? }
            // n = 4, score = 100
            //   752f                 | dec                 eax
            //   488d0d2a9b0000       | lea                 edx, [0x4c2c]
            //   e8????????           |                     
            //   ff15????????         |                     

        $sequence_3 = { 85db 7457 33c0 48898424b8000000 4889442430 }
            // n = 5, score = 100
            //   85db                 | je                  0xc24
            //   7457                 | dec                 eax
            //   33c0                 | lea                 edx, [0x4be5]
            //   48898424b8000000     | dec                 eax
            //   4889442430           | mov                 ecx, esi

        $sequence_4 = { 488d0dbf9c0000 e8???????? bb20040000 c78424b000000068000000 488d05939c0000 }
            // n = 5, score = 100
            //   488d0dbf9c0000       | test                eax, eax
            //   e8????????           |                     
            //   bb20040000           | je                  0x4fc
            //   c78424b000000068000000     | je    0x4f5
            //   488d05939c0000       | je                  0x4ee

        $sequence_5 = { 4533c9 448bc3 33d2 b900110000 ff15???????? 4c8b8424b8000000 }
            // n = 6, score = 100
            //   4533c9               | mov                 ecx, dword ptr [esp + 0x68]
            //   448bc3               | test                eax, eax
            //   33d2                 | jne                 0x123a
            //   b900110000           | dec                 eax
            //   ff15????????         |                     
            //   4c8b8424b8000000     | lea                 edx, [esp + 0x130]

        $sequence_6 = { ff15???????? 488905???????? 4885ff 742e }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   488905????????       |                     
            //   4885ff               | inc                 ecx
            //   742e                 | cmp                 eax, edi

        $sequence_7 = { 488d8c2430010000 ff15???????? 33d2 488d8c2430010000 ff15???????? }
            // n = 5, score = 100
            //   488d8c2430010000     | inc                 ecx
            //   ff15????????         |                     
            //   33d2                 | cmp                 eax, esi
            //   488d8c2430010000     | jae                 0x493
            //   ff15????????         |                     

        $sequence_8 = { ff15???????? 4c8b8424b8000000 8bd3 488d0dc7970000 e8???????? 488b8c24b8000000 ff15???????? }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   4c8b8424b8000000     | mov                 dword ptr [ebp - 0x10], eax
            //   8bd3                 | dec                 eax
            //   488d0dc7970000       | lea                 ecx, [ebp - 0x30]
            //   e8????????           |                     
            //   488b8c24b8000000     | mov                 dword ptr [ebp - 0x30], 0x6e72656b
            //   ff15????????         |                     

        $sequence_9 = { 8bb424a0000000 448bc6 8bd7 488d0d12990000 }
            // n = 4, score = 100
            //   8bb424a0000000       | mov                 dword ptr [ebp - 0x30], 0x6e72656b
            //   448bc6               | mov                 dword ptr [ebp - 0x2c], 0x32336c65
            //   8bd7                 | mov                 dword ptr [ebp - 0x28], 0x6c6c642e
            //   488d0d12990000       | dec                 eax

    condition:
        7 of them and filesize < 174080
}