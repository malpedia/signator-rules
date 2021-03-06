rule win_rhttpctrl_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.rhttpctrl."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rhttpctrl"
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
        $sequence_0 = { 6bf838 8955f8 8b149530424200 897df4 8a5c3a29 80fb02 }
            // n = 6, score = 100
            //   6bf838               | imul                edi, eax, 0x38
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   8b149530424200       | mov                 edx, dword ptr [edx*4 + 0x424230]
            //   897df4               | mov                 dword ptr [ebp - 0xc], edi
            //   8a5c3a29             | mov                 bl, byte ptr [edx + edi + 0x29]
            //   80fb02               | cmp                 bl, 2

        $sequence_1 = { 894104 a0???????? 884108 8d442420 50 8d44243c 50 }
            // n = 7, score = 100
            //   894104               | mov                 dword ptr [ecx + 4], eax
            //   a0????????           |                     
            //   884108               | mov                 byte ptr [ecx + 8], al
            //   8d442420             | lea                 eax, [esp + 0x20]
            //   50                   | push                eax
            //   8d44243c             | lea                 eax, [esp + 0x3c]
            //   50                   | push                eax

        $sequence_2 = { e8???????? 6810270000 ffd6 8b85e4fbffff ebe2 6800040000 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   6810270000           | push                0x2710
            //   ffd6                 | call                esi
            //   8b85e4fbffff         | mov                 eax, dword ptr [ebp - 0x41c]
            //   ebe2                 | jmp                 0xffffffe4
            //   6800040000           | push                0x400

        $sequence_3 = { 6800040000 8d85f0fbffff 6a00 50 e8???????? ffb5dcfbffff }
            // n = 6, score = 100
            //   6800040000           | push                0x400
            //   8d85f0fbffff         | lea                 eax, [ebp - 0x410]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     
            //   ffb5dcfbffff         | push                dword ptr [ebp - 0x424]

        $sequence_4 = { 85c0 c745f800000000 0f49f8 8b4510 }
            // n = 4, score = 100
            //   85c0                 | test                eax, eax
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0
            //   0f49f8               | cmovns              edi, eax
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]

        $sequence_5 = { c7460c00000000 c7461000000000 c7461400000000 c7461800000000 66c7461c0000 }
            // n = 5, score = 100
            //   c7460c00000000       | mov                 dword ptr [esi + 0xc], 0
            //   c7461000000000       | mov                 dword ptr [esi + 0x10], 0
            //   c7461400000000       | mov                 dword ptr [esi + 0x14], 0
            //   c7461800000000       | mov                 dword ptr [esi + 0x18], 0
            //   66c7461c0000         | mov                 word ptr [esi + 0x1c], 0

        $sequence_6 = { 3bc1 7410 50 e8???????? 83c404 0f1085c0feffff 8b4508 }
            // n = 7, score = 100
            //   3bc1                 | cmp                 eax, ecx
            //   7410                 | je                  0x12
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   0f1085c0feffff       | movups              xmm0, xmmword ptr [ebp - 0x140]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_7 = { c745fcffffffff 83c404 8b95e8d7ffff 83c8ff }
            // n = 4, score = 100
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   83c404               | add                 esp, 4
            //   8b95e8d7ffff         | mov                 edx, dword ptr [ebp - 0x2818]
            //   83c8ff               | or                  eax, 0xffffffff

        $sequence_8 = { 85f6 7456 85ff 7513 e8???????? 5f }
            // n = 6, score = 100
            //   85f6                 | test                esi, esi
            //   7456                 | je                  0x58
            //   85ff                 | test                edi, edi
            //   7513                 | jne                 0x15
            //   e8????????           |                     
            //   5f                   | pop                 edi

        $sequence_9 = { 85d2 7409 837e0400 7403 c60200 33c0 33c9 }
            // n = 7, score = 100
            //   85d2                 | test                edx, edx
            //   7409                 | je                  0xb
            //   837e0400             | cmp                 dword ptr [esi + 4], 0
            //   7403                 | je                  5
            //   c60200               | mov                 byte ptr [edx], 0
            //   33c0                 | xor                 eax, eax
            //   33c9                 | xor                 ecx, ecx

    condition:
        7 of them and filesize < 339968
}