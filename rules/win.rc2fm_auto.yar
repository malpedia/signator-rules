rule win_rc2fm_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.rc2fm."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rc2fm"
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
        $sequence_0 = { 488bf2 488be9 488d15a7fb0000 488bce 498bf8 ff15???????? 488bd8 }
            // n = 7, score = 100
            //   488bf2               | je                  0x108f
            //   488be9               | mov                 eax, dword ptr [ebp + 0x250]
            //   488d15a7fb0000       | dec                 eax
            //   488bce               | mov                 edx, esi
            //   498bf8               | dec                 eax
            //   ff15????????         |                     
            //   488bd8               | sub                 edx, eax

        $sequence_1 = { 75ef 8b4dc7 488d4503 448d8f0080ffff c644243000 4889442428 488d4507 }
            // n = 7, score = 100
            //   75ef                 | mov                 eax, dword ptr [ebp + 0x210]
            //   8b4dc7               | dec                 eax
            //   488d4503             | mov                 dword ptr [esp + 0x260], ebx
            //   448d8f0080ffff       | dec                 eax
            //   c644243000           | mov                 dword ptr [esp + 0x268], esi
            //   4889442428           | dec                 eax
            //   488d4507             | mov                 esi, dword ptr [eax]

        $sequence_2 = { 488b5318 488bc8 4c897c2438 488d45b7 4c8d8de8060000 4889442430 488d85f0060000 }
            // n = 7, score = 100
            //   488b5318             | dec                 ebp
            //   488bc8               | test                edx, edx
            //   4c897c2438           | je                  0x179f
            //   488d45b7             | inc                 cx
            //   4c8d8de8060000       | cmp                 dword ptr [eax + 0x58], 0x18
            //   4889442430           | jne                 0x178a
            //   488d85f0060000       | dec                 ecx

        $sequence_3 = { ba00000400 b913000100 448bc0 e8???????? eb48 48895c2440 48897c2448 }
            // n = 7, score = 100
            //   ba00000400           | jmp                 0xf72
            //   b913000100           | inc                 eax
            //   448bc0               | xor                 bh, bh
            //   e8????????           |                     
            //   eb48                 | dec                 eax
            //   48895c2440           | mov                 ecx, ebp
            //   48897c2448           | jmp                 0xf6c

        $sequence_4 = { 0fb6c0 894573 4d8b4508 488d4d70 488bd7 e8???????? 83f8ff }
            // n = 7, score = 100
            //   0fb6c0               | mov                 dword ptr [esp + 0x18], esi
            //   894573               | push                edi
            //   4d8b4508             | dec                 eax
            //   488d4d70             | sub                 esp, 0x4a0
            //   488bd7               | dec                 eax
            //   e8????????           |                     
            //   83f8ff               | mov                 ebp, ecx

        $sequence_5 = { 400fb6de eb4d ba05000100 448bc0 8d4a0a e8???????? 488b0d???????? }
            // n = 7, score = 100
            //   400fb6de             | lea                 eax, [esp + 0x30]
            //   eb4d                 | dec                 eax
            //   ba05000100           | mov                 ecx, eax
            //   448bc0               | dec                 eax
            //   8d4a0a               | mov                 edx, dword ptr [edx + 0x258]
            //   e8????????           |                     
            //   488b0d????????       |                     

        $sequence_6 = { 488bcf ff15???????? 85c0 741b b001 488b9c2490040000 488bb42498040000 }
            // n = 7, score = 100
            //   488bcf               | inc                 ecx
            //   ff15????????         |                     
            //   85c0                 | cmovne              ebx, esi
            //   741b                 | mov                 dword ptr [eax], ebx
            //   b001                 | dec                 esp
            //   488b9c2490040000     | lea                 ebx, [esp + 0x60]
            //   488bb42498040000     | inc                 eax

        $sequence_7 = { 0f84b8000000 48896c2438 4c89742420 4533f6 418bee 4439713c 7675 }
            // n = 7, score = 100
            //   0f84b8000000         | mov                 edi, dword ptr [esp + 0x48]
            //   48896c2438           | dec                 eax
            //   4c89742420           | mov                 ebp, dword ptr [esp + 0x90]
            //   4533f6               | dec                 esp
            //   418bee               | mov                 edi, dword ptr [esp + 0x40]
            //   4439713c             | dec                 eax
            //   7675                 | mov                 dword ptr [edx + eax*8], ebp

        $sequence_8 = { 7516 4885ff 7509 4c897908 4c8939 eb28 488939 }
            // n = 7, score = 100
            //   7516                 | mov                 edx, 0x10017
            //   4885ff               | inc                 esp
            //   7509                 | mov                 eax, ebx
            //   4c897908             | mov                 edx, 0x10019
            //   4c8939               | lea                 ecx, [edx + 4]
            //   eb28                 | dec                 ecx
            //   488939               | mov                 edx, ebp

        $sequence_9 = { 418b5228 498b4210 0fb7cb 66f7d1 66c1e908 880c02 41ff4228 }
            // n = 7, score = 100
            //   418b5228             | dec                 esp
            //   498b4210             | mov                 dword ptr [esp + 0x40], esi
            //   0fb7cb               | dec                 esp
            //   66f7d1               | mov                 esi, dword ptr [esi + 0x210]
            //   66c1e908             | dec                 ecx
            //   880c02               | mov                 ebx, dword ptr [esi]
            //   41ff4228             | dec                 eax

    condition:
        7 of them and filesize < 410624
}