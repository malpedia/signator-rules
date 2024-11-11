rule win_lobshot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.lobshot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lobshot"
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
        $sequence_0 = { 8b5c2414 8b35???????? 8d442448 50 57 ffd6 eb06 }
            // n = 7, score = 200
            //   8b5c2414             | mov                 ebx, dword ptr [esp + 0x14]
            //   8b35????????         |                     
            //   8d442448             | lea                 eax, [esp + 0x48]
            //   50                   | push                eax
            //   57                   | push                edi
            //   ffd6                 | call                esi
            //   eb06                 | jmp                 8

        $sequence_1 = { ffd5 85c0 7429 6a00 ff35???????? 6a00 50 }
            // n = 7, score = 200
            //   ffd5                 | call                ebp
            //   85c0                 | test                eax, eax
            //   7429                 | je                  0x2b
            //   6a00                 | push                0
            //   ff35????????         |                     
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_2 = { fec0 5e 88411c 5b c3 56 8bf1 }
            // n = 7, score = 200
            //   fec0                 | inc                 al
            //   5e                   | pop                 esi
            //   88411c               | mov                 byte ptr [ecx + 0x1c], al
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx

        $sequence_3 = { 8bf9 895df8 8b430c 8945fc 8b7730 8b4734 3bf0 }
            // n = 7, score = 200
            //   8bf9                 | mov                 edi, ecx
            //   895df8               | mov                 dword ptr [ebp - 8], ebx
            //   8b430c               | mov                 eax, dword ptr [ebx + 0xc]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b7730               | mov                 esi, dword ptr [edi + 0x30]
            //   8b4734               | mov                 eax, dword ptr [edi + 0x34]
            //   3bf0                 | cmp                 esi, eax

        $sequence_4 = { ffd5 33c0 66898424c8020000 8d442470 50 8d8424cc020000 }
            // n = 6, score = 200
            //   ffd5                 | call                ebp
            //   33c0                 | xor                 eax, eax
            //   66898424c8020000     | mov                 word ptr [esp + 0x2c8], ax
            //   8d442470             | lea                 eax, [esp + 0x70]
            //   50                   | push                eax
            //   8d8424cc020000       | lea                 eax, [esp + 0x2cc]

        $sequence_5 = { 57 33ed 89542464 8d442458 c74424581e000000 50 }
            // n = 6, score = 200
            //   57                   | push                edi
            //   33ed                 | xor                 ebp, ebp
            //   89542464             | mov                 dword ptr [esp + 0x64], edx
            //   8d442458             | lea                 eax, [esp + 0x58]
            //   c74424581e000000     | mov                 dword ptr [esp + 0x58], 0x1e
            //   50                   | push                eax

        $sequence_6 = { 8b5614 8b4e08 8a86b1160000 88040a b110 2a8eb4160000 8b45e4 }
            // n = 7, score = 200
            //   8b5614               | mov                 edx, dword ptr [esi + 0x14]
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]
            //   8a86b1160000         | mov                 al, byte ptr [esi + 0x16b1]
            //   88040a               | mov                 byte ptr [edx + ecx], al
            //   b110                 | mov                 cl, 0x10
            //   2a8eb4160000         | sub                 cl, byte ptr [esi + 0x16b4]
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]

        $sequence_7 = { c744242400000000 ff15???????? 85c0 7520 6a04 8d442414 50 }
            // n = 7, score = 200
            //   c744242400000000     | mov                 dword ptr [esp + 0x24], 0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7520                 | jne                 0x22
            //   6a04                 | push                4
            //   8d442414             | lea                 eax, [esp + 0x14]
            //   50                   | push                eax

        $sequence_8 = { 33f6 8b4dec 8bd9 834df8ff f7db 8b55e4 8b840538ffffff }
            // n = 7, score = 200
            //   33f6                 | xor                 esi, esi
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   8bd9                 | mov                 ebx, ecx
            //   834df8ff             | or                  dword ptr [ebp - 8], 0xffffffff
            //   f7db                 | neg                 ebx
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]
            //   8b840538ffffff       | mov                 eax, dword ptr [ebp + eax - 0xc8]

        $sequence_9 = { 7405 48 85c0 7fe9 6683bc44bc0200002e 750a 33c9 }
            // n = 7, score = 200
            //   7405                 | je                  7
            //   48                   | dec                 eax
            //   85c0                 | test                eax, eax
            //   7fe9                 | jg                  0xffffffeb
            //   6683bc44bc0200002e     | cmp    word ptr [esp + eax*2 + 0x2bc], 0x2e
            //   750a                 | jne                 0xc
            //   33c9                 | xor                 ecx, ecx

    condition:
        7 of them and filesize < 247808
}