rule win_backswap_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.backswap."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.backswap"
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
        $sequence_0 = { 33c9 e9???????? b32a 397d14 7412 }
            // n = 5, score = 400
            //   33c9                 | xor                 ecx, ecx
            //   e9????????           |                     
            //   b32a                 | mov                 bl, 0x2a
            //   397d14               | cmp                 dword ptr [ebp + 0x14], edi
            //   7412                 | je                  0x14

        $sequence_1 = { c9 c21000 83f0ff 5e 5f 5a }
            // n = 6, score = 400
            //   c9                   | leave               
            //   c21000               | ret                 0x10
            //   83f0ff               | xor                 eax, 0xffffffff
            //   5e                   | pop                 esi
            //   5f                   | pop                 edi
            //   5a                   | pop                 edx

        $sequence_2 = { f366a5 59 5f 5e c9 c20c00 55 }
            // n = 7, score = 400
            //   f366a5               | rep movsw           word ptr es:[edi], word ptr [esi]
            //   59                   | pop                 ecx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   c9                   | leave               
            //   c20c00               | ret                 0xc
            //   55                   | push                ebp

        $sequence_3 = { 7404 8bce 8bd3 397d14 0f8e99000000 39750c 7e7b }
            // n = 7, score = 400
            //   7404                 | je                  6
            //   8bce                 | mov                 ecx, esi
            //   8bd3                 | mov                 edx, ebx
            //   397d14               | cmp                 dword ptr [ebp + 0x14], edi
            //   0f8e99000000         | jle                 0x9f
            //   39750c               | cmp                 dword ptr [ebp + 0xc], esi
            //   7e7b                 | jle                 0x7d

        $sequence_4 = { 8bdf 4b eb1c 85c9 7508 3bdf 7404 }
            // n = 7, score = 400
            //   8bdf                 | mov                 ebx, edi
            //   4b                   | dec                 ebx
            //   eb1c                 | jmp                 0x1e
            //   85c9                 | test                ecx, ecx
            //   7508                 | jne                 0xa
            //   3bdf                 | cmp                 ebx, edi
            //   7404                 | je                  6

        $sequence_5 = { 7404 8bce 8bd3 397d14 0f8e99000000 }
            // n = 5, score = 400
            //   7404                 | je                  6
            //   8bce                 | mov                 ecx, esi
            //   8bd3                 | mov                 edx, ebx
            //   397d14               | cmp                 dword ptr [ebp + 0x14], edi
            //   0f8e99000000         | jle                 0x9f

        $sequence_6 = { 33c9 e9???????? b32a 397d14 7412 47 }
            // n = 6, score = 400
            //   33c9                 | xor                 ecx, ecx
            //   e9????????           |                     
            //   b32a                 | mov                 bl, 0x2a
            //   397d14               | cmp                 dword ptr [ebp + 0x14], edi
            //   7412                 | je                  0x14
            //   47                   | inc                 edi

        $sequence_7 = { 51 fc 8b750c 8b7d08 8b4d10 d1e9 f366a5 }
            // n = 7, score = 400
            //   51                   | push                ecx
            //   fc                   | cld                 
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   d1e9                 | shr                 ecx, 1
            //   f366a5               | rep movsw           word ptr es:[edi], word ptr [esi]

        $sequence_8 = { f366a5 59 5f 5e c9 }
            // n = 5, score = 400
            //   f366a5               | rep movsw           word ptr es:[edi], word ptr [esi]
            //   59                   | pop                 ecx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   c9                   | leave               

        $sequence_9 = { ebd4 3c3f 74c4 3c2a 7508 8bdf 897508 }
            // n = 7, score = 400
            //   ebd4                 | jmp                 0xffffffd6
            //   3c3f                 | cmp                 al, 0x3f
            //   74c4                 | je                  0xffffffc6
            //   3c2a                 | cmp                 al, 0x2a
            //   7508                 | jne                 0xa
            //   8bdf                 | mov                 ebx, edi
            //   897508               | mov                 dword ptr [ebp + 8], esi

    condition:
        7 of them and filesize < 122880
}