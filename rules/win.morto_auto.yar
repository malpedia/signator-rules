rule win_morto_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.morto."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.morto"
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
        $sequence_0 = { eb0a 33c0 8a0419 41 8d440001 f6c401 }
            // n = 6, score = 200
            //   eb0a                 | jmp                 0xc
            //   33c0                 | xor                 eax, eax
            //   8a0419               | mov                 al, byte ptr [ecx + ebx]
            //   41                   | inc                 ecx
            //   8d440001             | lea                 eax, [eax + eax + 1]
            //   f6c401               | test                ah, 1

        $sequence_1 = { 741f ff750c ff7630 ff7508 }
            // n = 4, score = 200
            //   741f                 | je                  0x21
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7630               | push                dword ptr [esi + 0x30]
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_2 = { eb11 8bfe 83c9ff 33c0 }
            // n = 4, score = 200
            //   eb11                 | jmp                 0x13
            //   8bfe                 | mov                 edi, esi
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax

        $sequence_3 = { 7404 6a00 ffd0 c9 c3 33c0 }
            // n = 6, score = 200
            //   7404                 | je                  6
            //   6a00                 | push                0
            //   ffd0                 | call                eax
            //   c9                   | leave               
            //   c3                   | ret                 
            //   33c0                 | xor                 eax, eax

        $sequence_4 = { b86f6f7425 895dec c745f800200300 c745d453595354 c745d8454d5c57 }
            // n = 5, score = 200
            //   b86f6f7425           | mov                 eax, 0x25746f6f
            //   895dec               | mov                 dword ptr [ebp - 0x14], ebx
            //   c745f800200300       | mov                 dword ptr [ebp - 8], 0x32000
            //   c745d453595354       | mov                 dword ptr [ebp - 0x2c], 0x54535953
            //   c745d8454d5c57       | mov                 dword ptr [ebp - 0x28], 0x575c4d45

        $sequence_5 = { c745a05c737973 c745a474656d33 c745a8325c7772 c745ac6974652e c745b065786500 }
            // n = 5, score = 200
            //   c745a05c737973       | mov                 dword ptr [ebp - 0x60], 0x7379735c
            //   c745a474656d33       | mov                 dword ptr [ebp - 0x5c], 0x336d6574
            //   c745a8325c7772       | mov                 dword ptr [ebp - 0x58], 0x72775c32
            //   c745ac6974652e       | mov                 dword ptr [ebp - 0x54], 0x2e657469
            //   c745b065786500       | mov                 dword ptr [ebp - 0x50], 0x657865

        $sequence_6 = { 897120 668b06 6685c0 741f 53 8b590c }
            // n = 6, score = 200
            //   897120               | mov                 dword ptr [ecx + 0x20], esi
            //   668b06               | mov                 ax, word ptr [esi]
            //   6685c0               | test                ax, ax
            //   741f                 | je                  0x21
            //   53                   | push                ebx
            //   8b590c               | mov                 ebx, dword ptr [ecx + 0xc]

        $sequence_7 = { ffd2 5f 5e c3 55 8bec 51 }
            // n = 7, score = 200
            //   ffd2                 | call                edx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx

        $sequence_8 = { 33c0 eb05 1bc0 83d8ff 85c0 7412 8bf9 }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   eb05                 | jmp                 7
            //   1bc0                 | sbb                 eax, eax
            //   83d8ff               | sbb                 eax, -1
            //   85c0                 | test                eax, eax
            //   7412                 | je                  0x14
            //   8bf9                 | mov                 edi, ecx

        $sequence_9 = { 8b4601 46 3bc3 74cf }
            // n = 4, score = 200
            //   8b4601               | mov                 eax, dword ptr [esi + 1]
            //   46                   | inc                 esi
            //   3bc3                 | cmp                 eax, ebx
            //   74cf                 | je                  0xffffffd1

    condition:
        7 of them and filesize < 49152
}