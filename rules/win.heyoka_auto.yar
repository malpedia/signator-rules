rule win_heyoka_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.heyoka."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.heyoka"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
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
        $sequence_0 = { 8b45f0 25ff000000 83f80a 7529 }
            // n = 4, score = 100
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   25ff000000           | and                 eax, 0xff
            //   83f80a               | cmp                 eax, 0xa
            //   7529                 | jne                 0x2b

        $sequence_1 = { c1f803 8945fc eb11 8b5508 52 68???????? e8???????? }
            // n = 7, score = 100
            //   c1f803               | sar                 eax, 3
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   eb11                 | jmp                 0x13
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   52                   | push                edx
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_2 = { 8b95f8feffff 668b02 668985ecfeffff 8b8decfeffff 81e1ffff0000 51 8b95f8feffff }
            // n = 7, score = 100
            //   8b95f8feffff         | mov                 edx, dword ptr [ebp - 0x108]
            //   668b02               | mov                 ax, word ptr [edx]
            //   668985ecfeffff       | mov                 word ptr [ebp - 0x114], ax
            //   8b8decfeffff         | mov                 ecx, dword ptr [ebp - 0x114]
            //   81e1ffff0000         | and                 ecx, 0xffff
            //   51                   | push                ecx
            //   8b95f8feffff         | mov                 edx, dword ptr [ebp - 0x108]

        $sequence_3 = { 8945d8 837dd800 750c c745e400000000 e9???????? 8b45f0 }
            // n = 6, score = 100
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   837dd800             | cmp                 dword ptr [ebp - 0x28], 0
            //   750c                 | jne                 0xe
            //   c745e400000000       | mov                 dword ptr [ebp - 0x1c], 0
            //   e9????????           |                     
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]

        $sequence_4 = { a1???????? 894204 8b4df8 890d???????? c705????????00000000 b801000000 8be5 }
            // n = 7, score = 100
            //   a1????????           |                     
            //   894204               | mov                 dword ptr [edx + 4], eax
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   890d????????         |                     
            //   c705????????00000000     |     
            //   b801000000           | mov                 eax, 1
            //   8be5                 | mov                 esp, ebp

        $sequence_5 = { 56 57 8b7d0c 8b34bd04d00110 037510 f6c303 7506 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]
            //   8b34bd04d00110       | mov                 esi, dword ptr [edi*4 + 0x1001d004]
            //   037510               | add                 esi, dword ptr [ebp + 0x10]
            //   f6c303               | test                bl, 3
            //   7506                 | jne                 8

        $sequence_6 = { e8???????? 83c404 83c011 8be5 5d c3 55 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   83c011               | add                 eax, 0x11
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp

        $sequence_7 = { 894df8 8b45f8 83b80809000000 7404 }
            // n = 4, score = 100
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   83b80809000000       | cmp                 dword ptr [eax + 0x908], 0
            //   7404                 | je                  6

        $sequence_8 = { eb02 ebc9 837df002 7e6e 8b4de8 8b55f0 3b9158100000 }
            // n = 7, score = 100
            //   eb02                 | jmp                 4
            //   ebc9                 | jmp                 0xffffffcb
            //   837df002             | cmp                 dword ptr [ebp - 0x10], 2
            //   7e6e                 | jle                 0x70
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   3b9158100000         | cmp                 edx, dword ptr [ecx + 0x1058]

        $sequence_9 = { 33c9 8a4835 83f901 7509 c745e401000000 eb07 }
            // n = 6, score = 100
            //   33c9                 | xor                 ecx, ecx
            //   8a4835               | mov                 cl, byte ptr [eax + 0x35]
            //   83f901               | cmp                 ecx, 1
            //   7509                 | jne                 0xb
            //   c745e401000000       | mov                 dword ptr [ebp - 0x1c], 1
            //   eb07                 | jmp                 9

    condition:
        7 of them and filesize < 270336
}