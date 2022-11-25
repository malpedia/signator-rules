rule win_lookback_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.lookback."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lookback"
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
        $sequence_0 = { c70600000000 c705????????00000000 8b06 85c0 }
            // n = 4, score = 200
            //   c70600000000         | mov                 dword ptr [esi], 0
            //   c705????????00000000     |     
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   85c0                 | test                eax, eax

        $sequence_1 = { 88840410010000 40 3d00060000 72f1 }
            // n = 4, score = 200
            //   88840410010000       | mov                 byte ptr [esp + eax + 0x110], al
            //   40                   | inc                 eax
            //   3d00060000           | cmp                 eax, 0x600
            //   72f1                 | jb                  0xfffffff3

        $sequence_2 = { c644240800 88442415 e8???????? 8d4c240c 89442408 51 }
            // n = 6, score = 200
            //   c644240800           | mov                 byte ptr [esp + 8], 0
            //   88442415             | mov                 byte ptr [esp + 0x15], al
            //   e8????????           |                     
            //   8d4c240c             | lea                 ecx, [esp + 0xc]
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   51                   | push                ecx

        $sequence_3 = { 8bc8 6a01 83e103 6a02 f3a4 ff15???????? }
            // n = 6, score = 200
            //   8bc8                 | mov                 ecx, eax
            //   6a01                 | push                1
            //   83e103               | and                 ecx, 3
            //   6a02                 | push                2
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   ff15????????         |                     

        $sequence_4 = { 894c241c eb25 8b4010 3bc7 }
            // n = 4, score = 200
            //   894c241c             | mov                 dword ptr [esp + 0x1c], ecx
            //   eb25                 | jmp                 0x27
            //   8b4010               | mov                 eax, dword ptr [eax + 0x10]
            //   3bc7                 | cmp                 eax, edi

        $sequence_5 = { 68???????? f3ab 8b84246c030000 895c2420 }
            // n = 4, score = 200
            //   68????????           |                     
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8b84246c030000       | mov                 eax, dword ptr [esp + 0x36c]
            //   895c2420             | mov                 dword ptr [esp + 0x20], ebx

        $sequence_6 = { 7422 6a00 8d4c2404 6a20 51 6a03 }
            // n = 6, score = 200
            //   7422                 | je                  0x24
            //   6a00                 | push                0
            //   8d4c2404             | lea                 ecx, [esp + 4]
            //   6a20                 | push                0x20
            //   51                   | push                ecx
            //   6a03                 | push                3

        $sequence_7 = { 8d7a18 8bd1 c1e902 f3ab 8bca }
            // n = 5, score = 200
            //   8d7a18               | lea                 edi, [edx + 0x18]
            //   8bd1                 | mov                 edx, ecx
            //   c1e902               | shr                 ecx, 2
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8bca                 | mov                 ecx, edx

        $sequence_8 = { 33ca 8a542410 8a8c0c20010000 32d9 881c38 40 }
            // n = 6, score = 200
            //   33ca                 | xor                 ecx, edx
            //   8a542410             | mov                 dl, byte ptr [esp + 0x10]
            //   8a8c0c20010000       | mov                 cl, byte ptr [esp + ecx + 0x120]
            //   32d9                 | xor                 bl, cl
            //   881c38               | mov                 byte ptr [eax + edi], bl
            //   40                   | inc                 eax

        $sequence_9 = { 85c0 7409 50 e8???????? 83c404 c70600000000 e9???????? }
            // n = 7, score = 200
            //   85c0                 | test                eax, eax
            //   7409                 | je                  0xb
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   c70600000000         | mov                 dword ptr [esi], 0
            //   e9????????           |                     

    condition:
        7 of them and filesize < 131072
}