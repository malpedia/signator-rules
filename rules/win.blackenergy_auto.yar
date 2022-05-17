rule win_blackenergy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.blackenergy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackenergy"
        malpedia_rule_date = "20220513"
        malpedia_hash = "7f4b2229e6ae614d86d74917f6d5b41890e62a26"
        malpedia_version = "20220516"
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
        $sequence_0 = { c745d8696e6700 c745f05761726e c745f44f6e436c c745f86f736500 c745dc5761726e c745e04f6e436c c745e46f736541 }
            // n = 7, score = 200
            //   c745d8696e6700       | mov                 dword ptr [ebp - 0x28], 0x676e69
            //   c745f05761726e       | mov                 dword ptr [ebp - 0x10], 0x6e726157
            //   c745f44f6e436c       | mov                 dword ptr [ebp - 0xc], 0x6c436e4f
            //   c745f86f736500       | mov                 dword ptr [ebp - 8], 0x65736f
            //   c745dc5761726e       | mov                 dword ptr [ebp - 0x24], 0x6e726157
            //   c745e04f6e436c       | mov                 dword ptr [ebp - 0x20], 0x6c436e4f
            //   c745e46f736541       | mov                 dword ptr [ebp - 0x1c], 0x4165736f

        $sequence_1 = { 5f 5e 5b c9 c20400 ff7508 ff15???????? }
            // n = 7, score = 200
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   c20400               | ret                 4
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     

        $sequence_2 = { 8d45e4 50 8d45b8 50 c745b8536f6674 c745bc77617265 c745c05c4d6963 }
            // n = 7, score = 200
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   50                   | push                eax
            //   8d45b8               | lea                 eax, [ebp - 0x48]
            //   50                   | push                eax
            //   c745b8536f6674       | mov                 dword ptr [ebp - 0x48], 0x74666f53
            //   c745bc77617265       | mov                 dword ptr [ebp - 0x44], 0x65726177
            //   c745c05c4d6963       | mov                 dword ptr [ebp - 0x40], 0x63694d5c

        $sequence_3 = { 8d45ec 50 33db 8d45f8 50 895dec }
            // n = 6, score = 200
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   50                   | push                eax
            //   33db                 | xor                 ebx, ebx
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   895dec               | mov                 dword ptr [ebp - 0x14], ebx

        $sequence_4 = { 49 75ef 7516 03cb 83e103 85c9 }
            // n = 6, score = 200
            //   49                   | dec                 ecx
            //   75ef                 | jne                 0xfffffff1
            //   7516                 | jne                 0x18
            //   03cb                 | add                 ecx, ebx
            //   83e103               | and                 ecx, 3
            //   85c9                 | test                ecx, ecx

        $sequence_5 = { 7469 8b0b 56 56 8d542418 52 50 }
            // n = 7, score = 200
            //   7469                 | je                  0x6b
            //   8b0b                 | mov                 ecx, dword ptr [ebx]
            //   56                   | push                esi
            //   56                   | push                esi
            //   8d542418             | lea                 edx, [esp + 0x18]
            //   52                   | push                edx
            //   50                   | push                eax

        $sequence_6 = { 8906 ff15???????? 8bf8 85ff }
            // n = 4, score = 200
            //   8906                 | mov                 dword ptr [esi], eax
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi

        $sequence_7 = { 837d2000 740d 60 2b7508 2b7d10 57 56 }
            // n = 7, score = 200
            //   837d2000             | cmp                 dword ptr [ebp + 0x20], 0
            //   740d                 | je                  0xf
            //   60                   | pushal              
            //   2b7508               | sub                 esi, dword ptr [ebp + 8]
            //   2b7d10               | sub                 edi, dword ptr [ebp + 0x10]
            //   57                   | push                edi
            //   56                   | push                esi

        $sequence_8 = { eb32 394124 751b 397024 740e 8b5024 895124 }
            // n = 7, score = 200
            //   eb32                 | jmp                 0x34
            //   394124               | cmp                 dword ptr [ecx + 0x24], eax
            //   751b                 | jne                 0x1d
            //   397024               | cmp                 dword ptr [eax + 0x24], esi
            //   740e                 | je                  0x10
            //   8b5024               | mov                 edx, dword ptr [eax + 0x24]
            //   895124               | mov                 dword ptr [ecx + 0x24], edx

        $sequence_9 = { c745dc6f726572 c745e05c496e66 c745e46f726d61 c745e874696f6e c745ec42617200 }
            // n = 5, score = 200
            //   c745dc6f726572       | mov                 dword ptr [ebp - 0x24], 0x7265726f
            //   c745e05c496e66       | mov                 dword ptr [ebp - 0x20], 0x666e495c
            //   c745e46f726d61       | mov                 dword ptr [ebp - 0x1c], 0x616d726f
            //   c745e874696f6e       | mov                 dword ptr [ebp - 0x18], 0x6e6f6974
            //   c745ec42617200       | mov                 dword ptr [ebp - 0x14], 0x726142

    condition:
        7 of them and filesize < 98304
}