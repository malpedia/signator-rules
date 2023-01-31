rule win_clambling_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.clambling."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clambling"
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
        $sequence_0 = { 488bcb ff15???????? 33c0 488b5c2438 }
            // n = 4, score = 300
            //   488bcb               | arpl                ax, cx
            //   ff15????????         |                     
            //   33c0                 | dec                 eax
            //   488b5c2438           | mov                 eax, dword ptr [ebx + ecx*8 + 0xc1e8]

        $sequence_1 = { 40887018 40887019 4088701a 4088701b 4088701c }
            // n = 5, score = 300
            //   40887018             | jne                 0x6e8
            //   40887019             | dec                 eax
            //   4088701a             | mov                 ecx, ebx
            //   4088701b             | je                  0x6ee
            //   4088701c             | mov                 eax, dword ptr [esi + 0x10]

        $sequence_2 = { 6645898b62ffffff 668984248c000000 b844000000 668984248e000000 }
            // n = 4, score = 300
            //   6645898b62ffffff     | inc                 ecx
            //   668984248c000000     | cmp                 eax, edi
            //   b844000000           | jne                 0x1f39
            //   668984248e000000     | dec                 eax

        $sequence_3 = { 4889b42438010000 4885ff 0f859b000000 33c0 488dbc24b0000000 b968000000 }
            // n = 6, score = 300
            //   4889b42438010000     | dec                 esp
            //   4885ff               | mov                 ecx, esi
            //   0f859b000000         | inc                 ecx
            //   33c0                 | mov                 edx, edx
            //   488dbc24b0000000     | je                  0x635
            //   b968000000           | dec                 esp

        $sequence_4 = { 48895c2408 57 4883ec30 33db 488bf9 215c2448 48215c2458 }
            // n = 7, score = 300
            //   48895c2408           | dec                 eax
            //   57                   | test                eax, eax
            //   4883ec30             | jne                 0x1243
            //   33db                 | mov                 edi, eax
            //   488bf9               | jmp                 0x1253
            //   215c2448             | dec                 eax
            //   48215c2458           | mov                 esi, eax

        $sequence_5 = { 8bd8 488b4c2460 483bce 7410 }
            // n = 4, score = 300
            //   8bd8                 | lea                 ecx, [esp + 0x280]
            //   488b4c2460           | inc                 esp
            //   483bce               | movzx               ebx, word ptr [esp + 0x50]
            //   7410                 | movzx               eax, word ptr [esp + 0x40]

        $sequence_6 = { ff15???????? 4863f8 85c0 7575 }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   4863f8               | mov                 ebp, ecx
            //   85c0                 | inc                 esp
            //   7575                 | lea                 eax, [edx + 0x78]

        $sequence_7 = { e8???????? 4c8d9c2450100000 8bc7 498b5b18 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   4c8d9c2450100000     | mov                 dword ptr [esp + 0x28], edx
            //   8bc7                 | dec                 esp
            //   498b5b18             | lea                 ecx, [edi + 0x14]

        $sequence_8 = { 7516 488b8c2438010000 488d542450 ff15???????? 4863f8 488b8c2438010000 }
            // n = 6, score = 300
            //   7516                 | jmp                 0x1e14
            //   488b8c2438010000     | inc                 ebx
            //   488d542450           | dec                 eax
            //   ff15????????         |                     
            //   4863f8               | inc                 edi
            //   488b8c2438010000     | jmp                 0x1dca

        $sequence_9 = { 4885db 7408 488bcb e8???????? 488b5c2458 488b742460 8bc7 }
            // n = 7, score = 300
            //   4885db               | mov                 ecx, edi
            //   7408                 | jmp                 0x489
            //   488bcb               | cmp                 eax, 3
            //   e8????????           |                     
            //   488b5c2458           | jne                 0x489
            //   488b742460           | dec                 eax
            //   8bc7                 | lea                 ecx, [edi + 0x198]

    condition:
        7 of them and filesize < 412672
}