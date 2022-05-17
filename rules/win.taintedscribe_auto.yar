rule win_taintedscribe_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.taintedscribe."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.taintedscribe"
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
        $sequence_0 = { 0f8565feffff 668b95a4fbffff 83431010 6689957cfbffff 8b430c }
            // n = 5, score = 500
            //   0f8565feffff         | jne                 0xfffffe6b
            //   668b95a4fbffff       | mov                 dx, word ptr [ebp - 0x45c]
            //   83431010             | add                 dword ptr [ebx + 0x10], 0x10
            //   6689957cfbffff       | mov                 word ptr [ebp - 0x484], dx
            //   8b430c               | mov                 eax, dword ptr [ebx + 0xc]

        $sequence_1 = { 33ff 83e001 740a c745a401000000 }
            // n = 4, score = 500
            //   33ff                 | xor                 edi, edi
            //   83e001               | and                 eax, 1
            //   740a                 | je                  0xc
            //   c745a401000000       | mov                 dword ptr [ebp - 0x5c], 1

        $sequence_2 = { 8bf8 f3a5 8b4b28 83c414 85c9 7518 5f }
            // n = 7, score = 500
            //   8bf8                 | mov                 edi, eax
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8b4b28               | mov                 ecx, dword ptr [ebx + 0x28]
            //   83c414               | add                 esp, 0x14
            //   85c9                 | test                ecx, ecx
            //   7518                 | jne                 0x1a
            //   5f                   | pop                 edi

        $sequence_3 = { 33ff 894d08 8bff 8b4508 }
            // n = 4, score = 500
            //   33ff                 | xor                 edi, edi
            //   894d08               | mov                 dword ptr [ebp + 8], ecx
            //   8bff                 | mov                 edi, edi
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_4 = { 56 57 33db 68a8af0600 8bf9 895dfc }
            // n = 6, score = 500
            //   56                   | push                esi
            //   57                   | push                edi
            //   33db                 | xor                 ebx, ebx
            //   68a8af0600           | push                0x6afa8
            //   8bf9                 | mov                 edi, ecx
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx

        $sequence_5 = { 8b5358 898d88fbffff 8b4b50 0f94c0 807b1400 899584fbffff 898d8cfbffff }
            // n = 7, score = 500
            //   8b5358               | mov                 edx, dword ptr [ebx + 0x58]
            //   898d88fbffff         | mov                 dword ptr [ebp - 0x478], ecx
            //   8b4b50               | mov                 ecx, dword ptr [ebx + 0x50]
            //   0f94c0               | sete                al
            //   807b1400             | cmp                 byte ptr [ebx + 0x14], 0
            //   899584fbffff         | mov                 dword ptr [ebp - 0x47c], edx
            //   898d8cfbffff         | mov                 dword ptr [ebp - 0x474], ecx

        $sequence_6 = { 5b 5d c20c00 83f803 7574 }
            // n = 5, score = 500
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c20c00               | ret                 0xc
            //   83f803               | cmp                 eax, 3
            //   7574                 | jne                 0x76

        $sequence_7 = { 5f 894328 5e 33c0 5b 8b4dfc 33cd }
            // n = 7, score = 500
            //   5f                   | pop                 edi
            //   894328               | mov                 dword ptr [ebx + 0x28], eax
            //   5e                   | pop                 esi
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   33cd                 | xor                 ecx, ebp

        $sequence_8 = { 897e5c 5f 894e3c 894e44 }
            // n = 4, score = 500
            //   897e5c               | mov                 dword ptr [esi + 0x5c], edi
            //   5f                   | pop                 edi
            //   894e3c               | mov                 dword ptr [esi + 0x3c], ecx
            //   894e44               | mov                 dword ptr [esi + 0x44], ecx

        $sequence_9 = { c20800 c7460c00000001 5f 5e }
            // n = 4, score = 500
            //   c20800               | ret                 8
            //   c7460c00000001       | mov                 dword ptr [esi + 0xc], 0x1000000
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

    condition:
        7 of them and filesize < 524288
}