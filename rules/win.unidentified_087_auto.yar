rule win_unidentified_087_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.unidentified_087."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_087"
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
        $sequence_0 = { 41ffc4 48ffc7 48ffc6 4889742420 4883ff04 }
            // n = 5, score = 200
            //   41ffc4               | inc                 ebp
            //   48ffc7               | test                esp, esp
            //   48ffc6               | je                  0x168
            //   4889742420           | dec                 ecx
            //   4883ff04             | arpl                sp, ax

        $sequence_1 = { 4032f6 8d4a02 ff15???????? 488bd8 4885c0 }
            // n = 5, score = 200
            //   4032f6               | inc                 eax
            //   8d4a02               | xor                 dh, dh
            //   ff15????????         |                     
            //   488bd8               | lea                 ecx, [edx + 2]
            //   4885c0               | dec                 eax

        $sequence_2 = { 488bc3 4a8d1429 488d0c38 4d8bc4 }
            // n = 4, score = 200
            //   488bc3               | jb                  0xf
            //   4a8d1429             | mov                 eax, 0xc0
            //   488d0c38             | cmp                 bx, ax
            //   4d8bc4               | jbe                 0x1d

        $sequence_3 = { 498bcc ff15???????? ffc0 03c0 }
            // n = 4, score = 200
            //   498bcc               | mov                 eax, 0x104
            //   ff15????????         |                     
            //   ffc0                 | dec                 eax
            //   03c0                 | lea                 edx, [ebp - 0x30]

        $sequence_4 = { b8ba000000 663bd8 720a b8c0000000 663bd8 760e b8db000000 }
            // n = 7, score = 200
            //   b8ba000000           | dec                 eax
            //   663bd8               | inc                 esi
            //   720a                 | dec                 eax
            //   b8c0000000           | mov                 dword ptr [esp + 0x20], esi
            //   663bd8               | dec                 eax
            //   760e                 | cmp                 edi, 4
            //   b8db000000           | inc                 ecx

        $sequence_5 = { 85c0 0f851ffeffff 4585e4 0f8459010000 4963c4 }
            // n = 5, score = 200
            //   85c0                 | mov                 ebx, eax
            //   0f851ffeffff         | dec                 eax
            //   4585e4               | test                eax, eax
            //   0f8459010000         | test                eax, eax
            //   4963c4               | jne                 0xfffffe25

        $sequence_6 = { 41b804010000 488d55d0 488bcf ff15???????? 33d2 }
            // n = 5, score = 200
            //   41b804010000         | inc                 ecx
            //   488d55d0             | inc                 esp
            //   488bcf               | dec                 eax
            //   ff15????????         |                     
            //   33d2                 | inc                 edi

        $sequence_7 = { 488b4710 488905???????? 488b4718 488905???????? 48c747180f000000 4c897710 c60700 }
            // n = 7, score = 200
            //   488b4710             | dec                 eax
            //   488905????????       |                     
            //   488b4718             | mov                 ecx, edi
            //   488905????????       |                     
            //   48c747180f000000     | xor                 edx, edx
            //   4c897710             | mov                 eax, 0xba
            //   c60700               | cmp                 bx, ax

        $sequence_8 = { 33c9 a3???????? 40 890d???????? a3???????? }
            // n = 5, score = 100
            //   33c9                 | lea                 ecx, [eax + edi]
            //   a3????????           |                     
            //   40                   | dec                 ebp
            //   890d????????         |                     
            //   a3????????           |                     

        $sequence_9 = { eb54 83460801 83560c00 8807 }
            // n = 4, score = 100
            //   eb54                 | mov                 eax, esp
            //   83460801             | inc                 ecx
            //   83560c00             | push                edi
            //   8807                 | dec                 eax

        $sequence_10 = { 8bec 56 8b7508 837e0800 7610 8b4608 8d800c1d0210 }
            // n = 7, score = 100
            //   8bec                 | dec                 eax
            //   56                   | mov                 dword ptr [esp + 0x30], 0xfffffffe
            //   8b7508               | dec                 esp
            //   837e0800             | mov                 esi, edx
            //   7610                 | push                0
            //   8b4608               | push                eax
            //   8d800c1d0210         | mov                 dword ptr [ebp - 0x160], ebx

        $sequence_11 = { 741f 83f805 741a 33c9 c705????????07000000 890d???????? }
            // n = 6, score = 100
            //   741f                 | xor                 eax, eax
            //   83f805               | add                 esp, 0xc
            //   741a                 | push                0x2000000
            //   33c9                 | mov                 dword ptr [ebp - 0x134], ebx
            //   c705????????07000000     |     
            //   890d????????         |                     

        $sequence_12 = { a3???????? a1???????? 68???????? 50 891d???????? c705????????07000000 }
            // n = 6, score = 100
            //   a3????????           |                     
            //   a1????????           |                     
            //   68????????           |                     
            //   50                   | sub                 esp, 0x48
            //   891d????????         |                     
            //   c705????????07000000     |     

        $sequence_13 = { 899dccfeffff 889dbcfeffff e8???????? 8b95a0feffff }
            // n = 4, score = 100
            //   899dccfeffff         | mov                 dword ptr [edi + 0x18], 0xf
            //   889dbcfeffff         | dec                 esp
            //   e8????????           |                     
            //   8b95a0feffff         | mov                 dword ptr [edi + 0x10], esi

        $sequence_14 = { 57 52 53 50 ff15???????? 8b8c242c040000 5f }
            // n = 7, score = 100
            //   57                   | mov                 byte ptr [edi], 0
            //   52                   | dec                 eax
            //   53                   | mov                 eax, ebx
            //   50                   | dec                 edx
            //   ff15????????         |                     
            //   8b8c242c040000       | lea                 edx, [ecx + ebp]
            //   5f                   | dec                 eax

        $sequence_15 = { 6a00 50 899da0feffff e8???????? 33c0 83c40c 6800000002 }
            // n = 7, score = 100
            //   6a00                 | add                 eax, eax
            //   50                   | dec                 eax
            //   899da0feffff         | mov                 eax, dword ptr [edi + 0x10]
            //   e8????????           |                     
            //   33c0                 | dec                 eax
            //   83c40c               | mov                 eax, dword ptr [edi + 0x18]
            //   6800000002           | dec                 eax

    condition:
        7 of them and filesize < 462848
}