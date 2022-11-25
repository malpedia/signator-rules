rule win_nabucur_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.nabucur."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nabucur"
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
        $sequence_0 = { 48 894500 85c0 7fee }
            // n = 4, score = 200
            //   48                   | dec                 eax
            //   894500               | mov                 dword ptr [ebp], eax
            //   85c0                 | test                eax, eax
            //   7fee                 | jg                  0xfffffff0

        $sequence_1 = { 49 23cf 894c241c 3bc3 }
            // n = 4, score = 200
            //   49                   | dec                 ecx
            //   23cf                 | and                 ecx, edi
            //   894c241c             | mov                 dword ptr [esp + 0x1c], ecx
            //   3bc3                 | cmp                 eax, ebx

        $sequence_2 = { 33ff 397c242c 7e61 8b6c242c 8b03 }
            // n = 5, score = 200
            //   33ff                 | xor                 edi, edi
            //   397c242c             | cmp                 dword ptr [esp + 0x2c], edi
            //   7e61                 | jle                 0x63
            //   8b6c242c             | mov                 ebp, dword ptr [esp + 0x2c]
            //   8b03                 | mov                 eax, dword ptr [ebx]

        $sequence_3 = { 48 8944241c 85c0 7fd1 5f }
            // n = 5, score = 200
            //   48                   | dec                 eax
            //   8944241c             | mov                 dword ptr [esp + 0x1c], eax
            //   85c0                 | test                eax, eax
            //   7fd1                 | jg                  0xffffffd3
            //   5f                   | pop                 edi

        $sequence_4 = { 49 23cb 894d08 5d }
            // n = 4, score = 200
            //   49                   | dec                 ecx
            //   23cb                 | and                 ecx, ebx
            //   894d08               | mov                 dword ptr [ebp + 8], ecx
            //   5d                   | pop                 ebp

        $sequence_5 = { 009eaa030000 0fb686aa030000 57 83f80a 0f876d010000 }
            // n = 5, score = 200
            //   009eaa030000         | add                 byte ptr [esi + 0x3aa], bl
            //   0fb686aa030000       | movzx               eax, byte ptr [esi + 0x3aa]
            //   57                   | push                edi
            //   83f80a               | cmp                 eax, 0xa
            //   0f876d010000         | ja                  0x173

        $sequence_6 = { 49 23ce 894f18 8bf0 85c0 0f8521040000 }
            // n = 6, score = 200
            //   49                   | dec                 ecx
            //   23ce                 | and                 ecx, esi
            //   894f18               | mov                 dword ptr [edi + 0x18], ecx
            //   8bf0                 | mov                 esi, eax
            //   85c0                 | test                eax, eax
            //   0f8521040000         | jne                 0x427

        $sequence_7 = { 49 03d3 40 85c9 }
            // n = 4, score = 200
            //   49                   | dec                 ecx
            //   03d3                 | add                 edx, ebx
            //   40                   | inc                 eax
            //   85c9                 | test                ecx, ecx

        $sequence_8 = { ba8fb4a3fb ebb8 83e904 83f905 7d02 ebd8 }
            // n = 6, score = 100
            //   ba8fb4a3fb           | mov                 edx, 0xfba3b48f
            //   ebb8                 | jmp                 0xffffffba
            //   83e904               | sub                 ecx, 4
            //   83f905               | cmp                 ecx, 5
            //   7d02                 | jge                 4
            //   ebd8                 | jmp                 0xffffffda

        $sequence_9 = { 83bdecfeffff00 750b 68f4010000 ff15???????? 83bdecfeffff00 }
            // n = 5, score = 100
            //   83bdecfeffff00       | cmp                 dword ptr [ebp - 0x114], 0
            //   750b                 | jne                 0xd
            //   68f4010000           | push                0x1f4
            //   ff15????????         |                     
            //   83bdecfeffff00       | cmp                 dword ptr [ebp - 0x114], 0

        $sequence_10 = { 5b 837d0c00 7519 ff75f4 ff75f8 }
            // n = 5, score = 100
            //   5b                   | pop                 ebx
            //   837d0c00             | cmp                 dword ptr [ebp + 0xc], 0
            //   7519                 | jne                 0x1b
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   ff75f8               | push                dword ptr [ebp - 8]

        $sequence_11 = { 81f37ed9e7fa bb764fedf8 3d32226f3d 0f8549b1fdff }
            // n = 4, score = 100
            //   81f37ed9e7fa         | xor                 ebx, 0xfae7d97e
            //   bb764fedf8           | mov                 ebx, 0xf8ed4f76
            //   3d32226f3d           | cmp                 eax, 0x3d6f2232
            //   0f8549b1fdff         | jne                 0xfffdb14f

        $sequence_12 = { c86ffdb0 55 7cf9 b055 }
            // n = 4, score = 100
            //   c86ffdb0             | enter               -0x291, -0x50
            //   55                   | push                ebp
            //   7cf9                 | jl                  0xfffffffb
            //   b055                 | mov                 al, 0x55

        $sequence_13 = { 93 ce f5 06 }
            // n = 4, score = 100
            //   93                   | xchg                eax, ebx
            //   ce                   | into                
            //   f5                   | cmc                 
            //   06                   | push                es

        $sequence_14 = { e283 7482 ec 8652a7 90 834ab6d4 }
            // n = 6, score = 100
            //   e283                 | loop                0xffffff85
            //   7482                 | je                  0xffffff84
            //   ec                   | in                  al, dx
            //   8652a7               | xchg                byte ptr [edx - 0x59], dl
            //   90                   | nop                 
            //   834ab6d4             | or                  dword ptr [edx - 0x4a], 0xffffffd4

        $sequence_15 = { 744b 8b45fc 8b5e04 2bc3 8b5608 }
            // n = 5, score = 100
            //   744b                 | je                  0x4d
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b5e04               | mov                 ebx, dword ptr [esi + 4]
            //   2bc3                 | sub                 eax, ebx
            //   8b5608               | mov                 edx, dword ptr [esi + 8]

    condition:
        7 of them and filesize < 1949696
}