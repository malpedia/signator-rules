rule win_newbounce_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.newbounce."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.newbounce"
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
        $sequence_0 = { 83e00f 7e05 2bf0 83c610 }
            // n = 4, score = 300
            //   83e00f               | and                 eax, 0xf
            //   7e05                 | jle                 7
            //   2bf0                 | sub                 esi, eax
            //   83c610               | add                 esi, 0x10

        $sequence_1 = { 488bcb 488bc3 488d1530bd0400 48c1f805 }
            // n = 4, score = 200
            //   488bcb               | mov                 ecx, eax
            //   488bc3               | dec                 eax
            //   488d1530bd0400       | lea                 ecx, [0x2ce6b]
            //   48c1f805             | dec                 eax

        $sequence_2 = { 488bcb 488905???????? ff15???????? 488d150ad20200 488bc8 }
            // n = 5, score = 200
            //   488bcb               | dec                 eax
            //   488905????????       |                     
            //   ff15????????         |                     
            //   488d150ad20200       | mov                 ecx, ebx
            //   488bc8               | dec                 eax

        $sequence_3 = { 488bcb 4889442422 8944242a 668944242e }
            // n = 4, score = 200
            //   488bcb               | mov                 ecx, ebx
            //   4889442422           | dec                 eax
            //   8944242a             | lea                 edx, [0x2d681]
            //   668944242e           | dec                 eax

        $sequence_4 = { 488bcb 488bc3 488d152f8e0400 48c1f805 }
            // n = 4, score = 200
            //   488bcb               | mov                 ecx, ebx
            //   488bc3               | dec                 eax
            //   488d152f8e0400       | mov                 ecx, ebx
            //   48c1f805             | dec                 eax

        $sequence_5 = { 488bcb 48891d???????? ff15???????? 488364242800 }
            // n = 4, score = 200
            //   488bcb               | mov                 ecx, eax
            //   48891d????????       |                     
            //   ff15????????         |                     
            //   488364242800         | dec                 eax

        $sequence_6 = { 488bcb 4c89742438 4889442440 e8???????? }
            // n = 4, score = 200
            //   488bcb               | lea                 edx, [0x2d495]
            //   4c89742438           | dec                 eax
            //   4889442440           | mov                 ecx, eax
            //   e8????????           |                     

        $sequence_7 = { 488bcb 4889442428 488d452f c7451f01000000 }
            // n = 4, score = 200
            //   488bcb               | mov                 ecx, ebx
            //   4889442428           | dec                 eax
            //   488d452f             | lea                 edx, [0x2d589]
            //   c7451f01000000       | dec                 eax

        $sequence_8 = { 7caf 8b45fc 5f 5b }
            // n = 4, score = 100
            //   7caf                 | lea                 edx, [0x2d3b1]
            //   8b45fc               | dec                 eax
            //   5f                   | mov                 ecx, ebx
            //   5b                   | dec                 eax

        $sequence_9 = { 7ca8 33db 8d45ec 50 ff7620 ffd7 }
            // n = 6, score = 100
            //   7ca8                 | mov                 ecx, ebx
            //   33db                 | dec                 eax
            //   8d45ec               | lea                 edx, [0x2daa7]
            //   50                   | dec                 eax
            //   ff7620               | mov                 ecx, eax
            //   ffd7                 | dec                 eax

        $sequence_10 = { 7ca9 8b45ec c70002000000 e8???????? c20400 6814010000 }
            // n = 6, score = 100
            //   7ca9                 | mov                 ecx, ebx
            //   8b45ec               | dec                 eax
            //   c70002000000         | lea                 edx, [0x2d1aa]
            //   e8????????           |                     
            //   c20400               | dec                 eax
            //   6814010000           | mov                 ecx, ebx

        $sequence_11 = { 7cab 8b5dfc 8d83c0000000 50 }
            // n = 4, score = 100
            //   7cab                 | mov                 ecx, ebx
            //   8b5dfc               | dec                 eax
            //   8d83c0000000         | lea                 edx, [0x2d1aa]
            //   50                   | dec                 eax

        $sequence_12 = { 7cae 33c0 3945e4 745c }
            // n = 4, score = 100
            //   7cae                 | lea                 edx, [0x2d0ab]
            //   33c0                 | dec                 eax
            //   3945e4               | mov                 ecx, eax
            //   745c                 | dec                 eax

        $sequence_13 = { 7cb1 5f 5e 5b c9 c20c00 }
            // n = 6, score = 100
            //   7cb1                 | mov                 ecx, ebx
            //   5f                   | dec                 eax
            //   5e                   | lea                 edx, [0x2d5b1]
            //   5b                   | dec                 eax
            //   c9                   | mov                 ecx, ebx
            //   c20c00               | dec                 eax

        $sequence_14 = { 7cae eb14 8b4c2414 8b542420 }
            // n = 4, score = 100
            //   7cae                 | mov                 ecx, ebx
            //   eb14                 | dec                 eax
            //   8b4c2414             | lea                 edx, [0x2d9af]
            //   8b542420             | dec                 eax

    condition:
        7 of them and filesize < 8637440
}