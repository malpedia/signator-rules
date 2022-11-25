rule win_proto8_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.proto8_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.proto8_rat"
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
        $sequence_0 = { 8bd0 488bcf e8???????? 8bf0 e9???????? b803000000 8903 }
            // n = 7, score = 100
            //   8bd0                 | inc                 ecx
            //   488bcf               | add                 ecx, edi
            //   e8????????           |                     
            //   8bf0                 | mov                 dword ptr [ebp - 0x28], ecx
            //   e9????????           |                     
            //   b803000000           | add                 dword ptr [ebp - 0x30], -1
            //   8903                 | jne                 0x4c6

        $sequence_1 = { 83f8db 7527 488b4b60 4c8d0534270400 8bd0 e8???????? b8dbffffff }
            // n = 7, score = 100
            //   83f8db               | je                  0x274
            //   7527                 | jae                 0x262
            //   488b4b60             | dec                 ecx
            //   4c8d0534270400       | sub                 eax, esi
            //   8bd0                 | dec                 eax
            //   e8????????           |                     
            //   b8dbffffff           | mov                 edx, eax

        $sequence_2 = { 4823c8 488b02 488b1cc8 41ffc0 453bc2 7c8e 418d70ff }
            // n = 7, score = 100
            //   4823c8               | inc                 ecx
            //   488b02               | cmovne              ecx, esi
            //   488b1cc8             | inc                 esp
            //   41ffc0               | mov                 esi, ecx
            //   453bc2               | dec                 eax
            //   7c8e                 | lea                 ecx, [esi + 0x88]
            //   418d70ff             | dec                 eax

        $sequence_3 = { 7448 488d9fb0000000 48895c2460 488bcb e8???????? 85c0 7408 }
            // n = 7, score = 100
            //   7448                 | test                eax, eax
            //   488d9fb0000000       | dec                 esp
            //   48895c2460           | lea                 ecx, [ebx + 0x1b8]
            //   488bcb               | dec                 ecx
            //   e8????????           |                     
            //   85c0                 | mov                 edx, esp
            //   7408                 | dec                 esp

        $sequence_4 = { 874710 b8ffffffff f00fc14708 83f801 7509 488b07 488bcf }
            // n = 7, score = 100
            //   874710               | dec                 eax
            //   b8ffffffff           | mov                 ecx, dword ptr [ebp + 0x450]
            //   f00fc14708           | dec                 eax
            //   83f801               | lea                 eax, [esp + 0x30]
            //   7509                 | jne                 0x29f
            //   488b07               | inc                 esp
            //   488bcf               | mov                 dword ptr [eax], esi

        $sequence_5 = { 75eb 0fb64341 488b7c2458 2c47 488bb42480000000 a8df 7517 }
            // n = 7, score = 100
            //   75eb                 | or                  cx, ax
            //   0fb64341             | mov                 eax, 0x600
            //   488b7c2458           | inc                 esp
            //   2c47                 | lea                 eax, [edi + 1]
            //   488bb42480000000     | cmp                 cx, ax
            //   a8df                 | jae                 0x10f
            //   7517                 | mov                 dword ptr [ebp + 0x1b8], 0x6603

        $sequence_6 = { ff15???????? 33d2 41b818010000 488d4c2464 e8???????? c74424601c010000 48897310 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   33d2                 | je                  0x264
            //   41b818010000         | dec                 eax
            //   488d4c2464           | mov                 ebx, dword ptr [esi + 8]
            //   e8????????           |                     
            //   c74424601c010000     | dec                 eax
            //   48897310             | lea                 ecx, [esp + 0x50]

        $sequence_7 = { 84c0 0f858c000000 b801000000 8783e0020000 ba01000000 488bcb e8???????? }
            // n = 7, score = 100
            //   84c0                 | and                 ecx, 0x1f
            //   0f858c000000         | je                  0x3f2
            //   b801000000           | dec                 ecx
            //   8783e0020000         | mov                 eax, dword ptr [eax + 8]
            //   ba01000000           | inc                 esp
            //   488bcb               | cmp                 byte ptr [eax + 0x19], dh
            //   e8????????           |                     

        $sequence_8 = { e8???????? 488b4b48 0fb601 3c2d 750e 834b3040 48ffc1 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488b4b48             | mov                 ecx, eax
            //   0fb601               | btr                 ecx, 0x1f
            //   3c2d                 | lock cmpxchg        dword ptr [ebx + 0x27c], ecx
            //   750e                 | je                  0x6b1
            //   834b3040             | nop                 dword ptr [eax + eax]
            //   48ffc1               | mov                 ecx, eax

        $sequence_9 = { 89442420 c744242401000000 c744242801000000 eb5f 83442424ff 0f44d6 89542428 }
            // n = 7, score = 100
            //   89442420             | xor                 eax, eax
            //   c744242401000000     | dec                 eax
            //   c744242801000000     | mov                 dword ptr [esp + 0x78], edi
            //   eb5f                 | dec                 eax
            //   83442424ff           | mov                 edi, dword ptr [esp + 0xa8]
            //   0f44d6               | jne                 0x5bb
            //   89542428             | dec                 eax

    condition:
        7 of them and filesize < 2537472
}