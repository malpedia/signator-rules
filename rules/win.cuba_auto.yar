rule win_cuba_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.cuba."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cuba"
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
        $sequence_0 = { 68???????? 64a100000000 50 53 81ec04010000 a1???????? 33c5 }
            // n = 7, score = 100
            //   68????????           |                     
            //   64a100000000         | mov                 eax, dword ptr fs:[0]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   81ec04010000         | sub                 esp, 0x104
            //   a1????????           |                     
            //   33c5                 | xor                 eax, ebp

        $sequence_1 = { 8907 33c0 5f 5d c3 6a1b 68???????? }
            // n = 7, score = 100
            //   8907                 | mov                 dword ptr [edi], eax
            //   33c0                 | xor                 eax, eax
            //   5f                   | pop                 edi
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   6a1b                 | push                0x1b
            //   68????????           |                     

        $sequence_2 = { 8b7dd4 894588 8b45c4 895db0 897d94 89458c 897590 }
            // n = 7, score = 100
            //   8b7dd4               | mov                 edi, dword ptr [ebp - 0x2c]
            //   894588               | mov                 dword ptr [ebp - 0x78], eax
            //   8b45c4               | mov                 eax, dword ptr [ebp - 0x3c]
            //   895db0               | mov                 dword ptr [ebp - 0x50], ebx
            //   897d94               | mov                 dword ptr [ebp - 0x6c], edi
            //   89458c               | mov                 dword ptr [ebp - 0x74], eax
            //   897590               | mov                 dword ptr [ebp - 0x70], esi

        $sequence_3 = { 8945ec 33c9 33c0 894dfc 8945d8 394518 0f8ec5040000 }
            // n = 7, score = 100
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   33c9                 | xor                 ecx, ecx
            //   33c0                 | xor                 eax, eax
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   394518               | cmp                 dword ptr [ebp + 0x18], eax
            //   0f8ec5040000         | jle                 0x4cb

        $sequence_4 = { 81c7???????? f3a5 5f 5e 5b 5d c3 }
            // n = 7, score = 100
            //   81c7????????         |                     
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c3                   | ret                 

        $sequence_5 = { 5b 8be5 5d c3 57 8d45f0 56 }
            // n = 7, score = 100
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   57                   | push                edi
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   56                   | push                esi

        $sequence_6 = { ff15???????? 85c0 751e ffd7 894304 32c0 5f }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   751e                 | jne                 0x20
            //   ffd7                 | call                edi
            //   894304               | mov                 dword ptr [ebx + 4], eax
            //   32c0                 | xor                 al, al
            //   5f                   | pop                 edi

        $sequence_7 = { 7d47 8d4510 50 ff15???????? 83c404 85c0 754a }
            // n = 7, score = 100
            //   7d47                 | jge                 0x49
            //   8d4510               | lea                 eax, [ebp + 0x10]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax
            //   754a                 | jne                 0x4c

        $sequence_8 = { 8956f8 8b46dc 33c2 8946fc 81ff???????? 7595 8b450c }
            // n = 7, score = 100
            //   8956f8               | mov                 dword ptr [esi - 8], edx
            //   8b46dc               | mov                 eax, dword ptr [esi - 0x24]
            //   33c2                 | xor                 eax, edx
            //   8946fc               | mov                 dword ptr [esi - 4], eax
            //   81ff????????         |                     
            //   7595                 | jne                 0xffffff97
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_9 = { c1ca16 8bc3 c1c806 33c8 8b85d4feffff 3385e4feffff 034ddc }
            // n = 7, score = 100
            //   c1ca16               | ror                 edx, 0x16
            //   8bc3                 | mov                 eax, ebx
            //   c1c806               | ror                 eax, 6
            //   33c8                 | xor                 ecx, eax
            //   8b85d4feffff         | mov                 eax, dword ptr [ebp - 0x12c]
            //   3385e4feffff         | xor                 eax, dword ptr [ebp - 0x11c]
            //   034ddc               | add                 ecx, dword ptr [ebp - 0x24]

    condition:
        7 of them and filesize < 1094656
}