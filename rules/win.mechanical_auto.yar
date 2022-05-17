rule win_mechanical_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.mechanical."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mechanical"
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
        $sequence_0 = { 03c7 3bca 72ed 5f }
            // n = 4, score = 200
            //   03c7                 | add                 esi, dword ptr [eax*4 + 0x42e5c0]
            //   3bca                 | mov                 dword ptr [ebp - 0x1c], 1
            //   72ed                 | xor                 ebx, ebx
            //   5f                   | cmp                 dword ptr [esi + 8], ebx

        $sequence_1 = { 75e8 4585c0 0f84d0010000 488d9424a0250000 458bc8 }
            // n = 5, score = 200
            //   75e8                 | nop                 
            //   4585c0               | cmp                 edx, 5
            //   0f84d0010000         | jge                 0x23
            //   488d9424a0250000     | dec                 eax
            //   458bc8               | arpl                dx, cx

        $sequence_2 = { 030495c0e54200 eb05 b8???????? f6400420 }
            // n = 4, score = 200
            //   030495c0e54200       | dec                 eax
            //   eb05                 | lea                 ecx, [0x82bb]
            //   b8????????           |                     
            //   f6400420             | dec                 eax

        $sequence_3 = { 033485c0e54200 c745e401000000 33db 395e08 }
            // n = 4, score = 200
            //   033485c0e54200       | test                byte ptr [eax + 4], 0x20
            //   c745e401000000       | je                  0x1b
            //   33db                 | push                ebx
            //   395e08               | push                0

        $sequence_4 = { 6690 420fb64419ff 4883e901 88840cd05b0000 75ed 488d8c24d05b0000 }
            // n = 6, score = 200
            //   6690                 | dec                 eax
            //   420fb64419ff         | mov                 esi, dword ptr [esp + 0x6880]
            //   4883e901             | dec                 esp
            //   88840cd05b0000       | mov                 esp, dword ptr [esp + 0x6870]
            //   75ed                 | dec                 eax
            //   488d8c24d05b0000     | mov                 edi, dword ptr [esp + 0x6878]

        $sequence_5 = { 8944244c 4533c9 4c8d15a841feff 41bb00020000 e9???????? 448b442464 }
            // n = 6, score = 200
            //   8944244c             | movzx               eax, word ptr [edi + ecx*2 + 0x10]
            //   4533c9               | inc                 edx
            //   4c8d15a841feff       | movzx               eax, byte ptr [ecx + ebx - 1]
            //   41bb00020000         | dec                 eax
            //   e9????????           |                     
            //   448b442464           | sub                 ecx, 1

        $sequence_6 = { 4c8d05942cfeff 66666690 83fa05 7d1a 4863ca 0fb7444f10 }
            // n = 6, score = 200
            //   4c8d05942cfeff       | nop                 
            //   66666690             | inc                 edx
            //   83fa05               | movzx               eax, byte ptr [ecx + ebx - 1]
            //   7d1a                 | dec                 eax
            //   4863ca               | sub                 ecx, 1
            //   0fb7444f10           | mov                 byte ptr [esp + ecx + 0x5bd0], al

        $sequence_7 = { 033485c0e54200 8b45e4 8b00 8906 }
            // n = 4, score = 200
            //   033485c0e54200       | add                 eax, dword ptr [edx*4 + 0x42e5c0]
            //   8b45e4               | jmp                 7
            //   8b00                 | test                byte ptr [eax + 4], 0x20
            //   8906                 | je                  0x1c

        $sequence_8 = { 7695 418bdc eb90 488bb42480680000 4c8ba42470680000 488bbc2478680000 }
            // n = 6, score = 200
            //   7695                 | mov                 ebx, esi
            //   418bdc               | cmp                 ecx, dword ptr [eax]
            //   eb90                 | jbe                 0xffffff97
            //   488bb42480680000     | inc                 ecx
            //   4c8ba42470680000     | mov                 ebx, esp
            //   488bbc2478680000     | jmp                 0xffffff95

        $sequence_9 = { c744242000000000 7511 488d0dbb820000 e8???????? 4883c438 c3 }
            // n = 6, score = 200
            //   c744242000000000     | mov                 byte ptr [esp + ecx + 0x4cf0], al
            //   7511                 | jne                 0xfffffff6
            //   488d0dbb820000       | dec                 eax
            //   e8????????           |                     
            //   4883c438             | lea                 ecx, [esp + 0x4cf0]
            //   c3                   | jne                 0xffffffea

        $sequence_10 = { 0401 3cbe 8844240b 76e2 }
            // n = 4, score = 200
            //   0401                 | add                 eax, edi
            //   3cbe                 | cmp                 ecx, edx
            //   8844240b             | jb                  0xfffffff1
            //   76e2                 | pop                 edi

        $sequence_11 = { 00686c 42 0023 d18a0688078a }
            // n = 4, score = 200
            //   00686c               | dec                 eax
            //   42                   | lea                 edx, [esp + 0x25a0]
            //   0023                 | inc                 ebp
            //   d18a0688078a         | mov                 ecx, eax

        $sequence_12 = { 03ce c6840c3801000000 8d8424a05c0000 33f6 }
            // n = 4, score = 200
            //   03ce                 | add                 esi, dword ptr [eax*4 + 0x42e5c0]
            //   c6840c3801000000     | mov                 dword ptr [ebp - 0x1c], 1
            //   8d8424a05c0000       | xor                 ebx, ebx
            //   33f6                 | cmp                 dword ptr [esi + 8], ebx

        $sequence_13 = { 03c1 1bc9 0bc1 59 e9???????? e8???????? ff742404 }
            // n = 7, score = 200
            //   03c1                 | mov                 eax, dword ptr [eax]
            //   1bc9                 | mov                 dword ptr [esi], eax
            //   0bc1                 | mov                 al, byte ptr [ebx]
            //   59                   | mov                 byte ptr [esi + 4], al
            //   e9????????           |                     
            //   e8????????           |                     
            //   ff742404             | push                0xfa0

        $sequence_14 = { 420fb64419ff 4883e901 88840cf04c0000 75ed 488d8c24f04c0000 }
            // n = 5, score = 200
            //   420fb64419ff         | jne                 0
            //   4883e901             | dec                 eax
            //   88840cf04c0000       | lea                 ecx, [esp + 0x5bd0]
            //   75ed                 | dec                 esp
            //   488d8c24f04c0000     | lea                 eax, [0xfffe2c94]

        $sequence_15 = { 4c8d25d1e20000 33f6 498bc4 8bf9 8bde 3b08 }
            // n = 6, score = 200
            //   4c8d25d1e20000       | dec                 esp
            //   33f6                 | lea                 esp, [0xe2d1]
            //   498bc4               | xor                 esi, esi
            //   8bf9                 | dec                 ecx
            //   8bde                 | mov                 eax, esp
            //   3b08                 | mov                 edi, ecx

    condition:
        7 of them and filesize < 434176
}