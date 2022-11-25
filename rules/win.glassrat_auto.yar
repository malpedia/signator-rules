rule win_glassrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.glassrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.glassrat"
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
        $sequence_0 = { 84c0 7478 8b4e08 33c0 49 }
            // n = 5, score = 200
            //   84c0                 | test                al, al
            //   7478                 | je                  0x7a
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]
            //   33c0                 | xor                 eax, eax
            //   49                   | dec                 ecx

        $sequence_1 = { 7317 8b4e04 898c85e8feffff 8b85e4feffff 40 8985e4feffff 8d55e8 }
            // n = 7, score = 200
            //   7317                 | jae                 0x19
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   898c85e8feffff       | mov                 dword ptr [ebp + eax*4 - 0x118], ecx
            //   8b85e4feffff         | mov                 eax, dword ptr [ebp - 0x11c]
            //   40                   | inc                 eax
            //   8985e4feffff         | mov                 dword ptr [ebp - 0x11c], eax
            //   8d55e8               | lea                 edx, [ebp - 0x18]

        $sequence_2 = { 50 ff15???????? 81c414010000 c21000 57 6a00 }
            // n = 6, score = 200
            //   50                   | push                eax
            //   ff15????????         |                     
            //   81c414010000         | add                 esp, 0x114
            //   c21000               | ret                 0x10
            //   57                   | push                edi
            //   6a00                 | push                0

        $sequence_3 = { 8b4c2408 81ec14010000 8bc1 83e802 }
            // n = 4, score = 200
            //   8b4c2408             | mov                 ecx, dword ptr [esp + 8]
            //   81ec14010000         | sub                 esp, 0x114
            //   8bc1                 | mov                 eax, ecx
            //   83e802               | sub                 eax, 2

        $sequence_4 = { 3bc8 b802000000 0f85b4000000 33d2 b909020000 52 83ec10 }
            // n = 7, score = 200
            //   3bc8                 | cmp                 ecx, eax
            //   b802000000           | mov                 eax, 2
            //   0f85b4000000         | jne                 0xba
            //   33d2                 | xor                 edx, edx
            //   b909020000           | mov                 ecx, 0x209
            //   52                   | push                edx
            //   83ec10               | sub                 esp, 0x10

        $sequence_5 = { 762e 33ff 85f6 7e28 8b54242c 8b4d04 }
            // n = 6, score = 200
            //   762e                 | jbe                 0x30
            //   33ff                 | xor                 edi, edi
            //   85f6                 | test                esi, esi
            //   7e28                 | jle                 0x2a
            //   8b54242c             | mov                 edx, dword ptr [esp + 0x2c]
            //   8b4d04               | mov                 ecx, dword ptr [ebp + 4]

        $sequence_6 = { 8b460c 53 53 57 50 }
            // n = 5, score = 200
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   57                   | push                edi
            //   50                   | push                eax

        $sequence_7 = { 8a4620 895dfc 84c0 7513 32c0 8b4df4 }
            // n = 6, score = 200
            //   8a4620               | mov                 al, byte ptr [esi + 0x20]
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   84c0                 | test                al, al
            //   7513                 | jne                 0x15
            //   32c0                 | xor                 al, al
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_8 = { 895de8 895508 aa 8955ec 8955fc 6a64 }
            // n = 6, score = 200
            //   895de8               | mov                 dword ptr [ebp - 0x18], ebx
            //   895508               | mov                 dword ptr [ebp + 8], edx
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8955ec               | mov                 dword ptr [ebp - 0x14], edx
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   6a64                 | push                0x64

        $sequence_9 = { 7509 32c0 5d 83c408 c21400 53 56 }
            // n = 7, score = 200
            //   7509                 | jne                 0xb
            //   32c0                 | xor                 al, al
            //   5d                   | pop                 ebp
            //   83c408               | add                 esp, 8
            //   c21400               | ret                 0x14
            //   53                   | push                ebx
            //   56                   | push                esi

    condition:
        7 of them and filesize < 81920
}