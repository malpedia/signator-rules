rule win_scieron_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.scieron."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.scieron"
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
        $sequence_0 = { 895c2420 33ff ff15???????? 85c0 7554 ff15???????? 53 }
            // n = 7, score = 100
            //   895c2420             | mov                 dword ptr [esp + 0x20], ebx
            //   33ff                 | xor                 edi, edi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7554                 | jne                 0x56
            //   ff15????????         |                     
            //   53                   | push                ebx

        $sequence_1 = { 40 c20c00 81ec0c020000 53 8b1d???????? }
            // n = 5, score = 100
            //   40                   | inc                 eax
            //   c20c00               | ret                 0xc
            //   81ec0c020000         | sub                 esp, 0x20c
            //   53                   | push                ebx
            //   8b1d????????         |                     

        $sequence_2 = { 897d0c 6a03 e8???????? 8bf8 83c410 }
            // n = 5, score = 100
            //   897d0c               | mov                 dword ptr [ebp + 0xc], edi
            //   6a03                 | push                3
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   83c410               | add                 esp, 0x10

        $sequence_3 = { ebaf 8b45fc 56 e8???????? ebb9 ff75fc }
            // n = 6, score = 100
            //   ebaf                 | jmp                 0xffffffb1
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   56                   | push                esi
            //   e8????????           |                     
            //   ebb9                 | jmp                 0xffffffbb
            //   ff75fc               | push                dword ptr [ebp - 4]

        $sequence_4 = { 85f6 0f95c0 5f 5e 5b c9 c3 }
            // n = 7, score = 100
            //   85f6                 | test                esi, esi
            //   0f95c0               | setne               al
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   c3                   | ret                 

        $sequence_5 = { 83c40c 85c0 7454 8b1d???????? }
            // n = 4, score = 100
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   7454                 | je                  0x56
            //   8b1d????????         |                     

        $sequence_6 = { 8b861c020000 85c0 7463 b980000000 }
            // n = 4, score = 100
            //   8b861c020000         | mov                 eax, dword ptr [esi + 0x21c]
            //   85c0                 | test                eax, eax
            //   7463                 | je                  0x65
            //   b980000000           | mov                 ecx, 0x80

        $sequence_7 = { 75de 6a00 ff15???????? 50 ff742418 33ff }
            // n = 6, score = 100
            //   75de                 | jne                 0xffffffe0
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff742418             | push                dword ptr [esp + 0x18]
            //   33ff                 | xor                 edi, edi

        $sequence_8 = { 3bfe 7419 8d4574 50 57 56 }
            // n = 6, score = 100
            //   3bfe                 | cmp                 edi, esi
            //   7419                 | je                  0x1b
            //   8d4574               | lea                 eax, [ebp + 0x74]
            //   50                   | push                eax
            //   57                   | push                edi
            //   56                   | push                esi

        $sequence_9 = { 53 8b1d???????? 55 33c0 57 }
            // n = 5, score = 100
            //   53                   | push                ebx
            //   8b1d????????         |                     
            //   55                   | push                ebp
            //   33c0                 | xor                 eax, eax
            //   57                   | push                edi

    condition:
        7 of them and filesize < 100352
}