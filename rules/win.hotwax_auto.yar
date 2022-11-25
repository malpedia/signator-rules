rule win_hotwax_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.hotwax."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hotwax"
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
        $sequence_0 = { ff15???????? 488d1531ce0000 488bcb 488905???????? }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   488d1531ce0000       | dec                 ecx
            //   488bcb               | mov                 ecx, ebx
            //   488905????????       |                     

        $sequence_1 = { 4b8b84f8a04b0100 f644300840 7507 804c300802 eb09 418a4500 }
            // n = 6, score = 100
            //   4b8b84f8a04b0100     | test                al, al
            //   f644300840           | jne                 0x26
            //   7507                 | add                 cx, cx
            //   804c300802           | dec                 ebp
            //   eb09                 | mov                 dword ptr [ebp + 0x50], ecx
            //   418a4500             | dec                 ebp

        $sequence_2 = { ff15???????? 488d1520d20000 488bcb 488905???????? ff15???????? }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   488d1520d20000       | dec                 eax
            //   488bcb               | mov                 edx, dword ptr [esp + 0x50]
            //   488905????????       |                     
            //   ff15????????         |                     

        $sequence_3 = { 4c8d05247bffff 4b8b84f8a04b0100 f644300848 743b ba0a000000 663955d8 7440 }
            // n = 7, score = 100
            //   4c8d05247bffff       | add                 ebp, 2
            //   4b8b84f8a04b0100     | dec                 ebx
            //   f644300848           | mov                 ecx, dword ptr [eax + edi*8 + 0x14ba0]
            //   743b                 | mov                 byte ptr [ecx + esi + 9], al
            //   ba0a000000           | mov                 al, byte ptr [ebp - 0x27]
            //   663955d8             | dec                 ebx
            //   7440                 | mov                 ecx, dword ptr [eax + edi*8 + 0x14ba0]

        $sequence_4 = { 4c8d05f8530000 498bd4 488bcd e8???????? 85c0 7541 }
            // n = 6, score = 100
            //   4c8d05f8530000       | lea                 eax, [edx + 1]
            //   498bd4               | dec                 esp
            //   488bcd               | lea                 ecx, [0xffff7fac]
            //   e8????????           |                     
            //   85c0                 | mov                 edx, dword ptr [esp + 0x40]
            //   7541                 | dec                 esp

        $sequence_5 = { 498b4538 4889542428 418b5540 4c03d5 }
            // n = 4, score = 100
            //   498b4538             | dec                 eax
            //   4889542428           | mov                 esi, ecx
            //   418b5540             | dec                 eax
            //   4c03d5               | lea                 ecx, [0xc6b1]

        $sequence_6 = { 498bd4 488bce 4c896588 4c896d90 48c744242000000000 }
            // n = 5, score = 100
            //   498bd4               | lea                 ebp, [edx + eax]
            //   488bce               | mov                 eax, dword ptr [edx + eax + 0xc]
            //   4c896588             | inc                 ecx
            //   4c896d90             | mov                 edi, dword ptr [edi + 0x88]
            //   48c744242000000000     | dec    eax

        $sequence_7 = { 442bd8 4c03d0 4183fb08 7f96 b801000000 4883c430 }
            // n = 6, score = 100
            //   442bd8               | lea                 edx, [0xd7ed]
            //   4c03d0               | dec                 eax
            //   4183fb08             | lea                 edx, [0x5816]
            //   7f96                 | dec                 eax
            //   b801000000           | lea                 ecx, [0x57ef]
            //   4883c430             | test                eax, eax

        $sequence_8 = { 663955d8 7416 eb0c ba0a000000 4c8d05927affff 66448923 }
            // n = 6, score = 100
            //   663955d8             | inc                 esp
            //   7416                 | mov                 esi, ecx
            //   eb0c                 | dec                 esi
            //   ba0a000000           | lea                 eax, [ecx + edi + 0x570]
            //   4c8d05927affff       | mov                 dword ptr [esp + 0x20], 0x40
            //   66448923             | dec                 esp

        $sequence_9 = { 8a45d9 4b8b8cf8a04b0100 88443139 4b8b84f8a04b0100 8854303a }
            // n = 5, score = 100
            //   8a45d9               | mov                 dword ptr [eax + edx*8], eax
            //   4b8b8cf8a04b0100     | dec                 eax
            //   88443139             | test                eax, eax
            //   4b8b84f8a04b0100     | je                  0xc4
            //   8854303a             | dec                 eax

    condition:
        7 of them and filesize < 198656
}