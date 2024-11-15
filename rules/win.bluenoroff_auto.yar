rule win_bluenoroff_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.bluenoroff."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bluenoroff"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
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
        $sequence_0 = { 68ffff0000 50 e8???????? 8b4508 83c41c 83f801 750e }
            // n = 7, score = 300
            //   68ffff0000           | push                0xffff
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83c41c               | add                 esp, 0x1c
            //   83f801               | cmp                 eax, 1
            //   750e                 | jne                 0x10

        $sequence_1 = { 68ffff0000 50 e8???????? 33c0 83c41c 8d95ecfffeff 33c9 }
            // n = 7, score = 300
            //   68ffff0000           | push                0xffff
            //   50                   | push                eax
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   83c41c               | add                 esp, 0x1c
            //   8d95ecfffeff         | lea                 edx, [ebp - 0x10014]
            //   33c9                 | xor                 ecx, ecx

        $sequence_2 = { 8bec b804000100 e8???????? a1???????? 33c5 8945fc 68ffff0000 }
            // n = 7, score = 300
            //   8bec                 | mov                 ebp, esp
            //   b804000100           | mov                 eax, 0x10004
            //   e8????????           |                     
            //   a1????????           |                     
            //   33c5                 | xor                 eax, ebp
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   68ffff0000           | push                0xffff

        $sequence_3 = { 8b45f8 40 81c348040000 8945f8 3b45ec 7c8e }
            // n = 6, score = 300
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   40                   | inc                 eax
            //   81c348040000         | add                 ebx, 0x448
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   3b45ec               | cmp                 eax, dword ptr [ebp - 0x14]
            //   7c8e                 | jl                  0xffffff90

        $sequence_4 = { b8b9757907 f7e2 c1ea05 83c40c 8955ec 895df8 3bd3 }
            // n = 7, score = 300
            //   b8b9757907           | mov                 eax, 0x77975b9
            //   f7e2                 | mul                 edx
            //   c1ea05               | shr                 edx, 5
            //   83c40c               | add                 esp, 0xc
            //   8955ec               | mov                 dword ptr [ebp - 0x14], edx
            //   895df8               | mov                 dword ptr [ebp - 8], ebx
            //   3bd3                 | cmp                 edx, ebx

        $sequence_5 = { 885431ff 0fb6550b 881430 81f900010000 7ccb 5f }
            // n = 6, score = 300
            //   885431ff             | mov                 byte ptr [ecx + esi - 1], dl
            //   0fb6550b             | movzx               edx, byte ptr [ebp + 0xb]
            //   881430               | mov                 byte ptr [eax + esi], dl
            //   81f900010000         | cmp                 ecx, 0x100
            //   7ccb                 | jl                  0xffffffcd
            //   5f                   | pop                 edi

        $sequence_6 = { 83c40c 8955ec 895df8 3bd3 }
            // n = 4, score = 300
            //   83c40c               | add                 esp, 0xc
            //   8955ec               | mov                 dword ptr [ebp - 0x14], edx
            //   895df8               | mov                 dword ptr [ebp - 8], ebx
            //   3bd3                 | cmp                 edx, ebx

        $sequence_7 = { 8bf0 83c408 85f6 743a 8d85fcfffeff 50 }
            // n = 6, score = 300
            //   8bf0                 | mov                 esi, eax
            //   83c408               | add                 esp, 8
            //   85f6                 | test                esi, esi
            //   743a                 | je                  0x3c
            //   8d85fcfffeff         | lea                 eax, [ebp - 0x10004]
            //   50                   | push                eax

        $sequence_8 = { a1???????? 33c5 8945fc 56 68ffff0000 8d85fdfffeff 6a00 }
            // n = 7, score = 300
            //   a1????????           |                     
            //   33c5                 | xor                 eax, ebp
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   56                   | push                esi
            //   68ffff0000           | push                0xffff
            //   8d85fdfffeff         | lea                 eax, [ebp - 0x10003]
            //   6a00                 | push                0

        $sequence_9 = { 83c709 57 894e04 e8???????? 83c40c }
            // n = 5, score = 300
            //   83c709               | add                 edi, 9
            //   57                   | push                edi
            //   894e04               | mov                 dword ptr [esi + 4], ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

    condition:
        7 of them and filesize < 303104
}