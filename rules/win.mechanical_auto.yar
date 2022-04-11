rule win_mechanical_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.mechanical."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mechanical"
        malpedia_rule_date = "20220405"
        malpedia_hash = "ecd38294bd47d5589be5cd5490dc8bb4804afc2a"
        malpedia_version = ""
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
            //   03c7                 | mov                 dword ptr [ebp - 0x1c], 1
            //   3bca                 | xor                 ebx, ebx
            //   72ed                 | cmp                 dword ptr [esi + 8], ebx
            //   5f                   | jne                 0x44

        $sequence_1 = { 00686c 42 0023 d18a0688078a }
            // n = 4, score = 200
            //   00686c               | nop                 
            //   42                   | inc                 ecx
            //   0023                 | movzx               eax, byte ptr [ebx + ecx - 1]
            //   d18a0688078a         | dec                 eax

        $sequence_2 = { 0f8492bb0000 8b442430 488d8c24a1140000 33d2 }
            // n = 4, score = 200
            //   0f8492bb0000         | mov                 ecx, esp
            //   8b442430             | dec                 ecx
            //   488d8c24a1140000     | mov                 edx, ebx
            //   33d2                 | movzx               eax, byte ptr [edx]

        $sequence_3 = { 0401 3cbe 8844240b 76e2 }
            // n = 4, score = 200
            //   0401                 | mov                 byte ptr [esp + ecx + 0x138], 0
            //   3cbe                 | lea                 eax, dword ptr [esp + 0x5ca0]
            //   8844240b             | xor                 esi, esi
            //   76e2                 | add                 ecx, esi

        $sequence_4 = { 033485c0e54200 c745e401000000 33db 395e08 }
            // n = 4, score = 200
            //   033485c0e54200       | mov                 eax, dword ptr [ebp - 0x1c]
            //   c745e401000000       | mov                 eax, dword ptr [eax]
            //   33db                 | mov                 dword ptr [esi], eax
            //   395e08               | add                 esi, dword ptr [eax*4 + 0x42e5c0]

        $sequence_5 = { 0f843ad80000 8b442430 488d8c24e1070000 33d2 41b803010000 }
            // n = 5, score = 200
            //   0f843ad80000         | dec                 eax
            //   8b442430             | lea                 edx, dword ptr [esp + 0x15b0]
            //   488d8c24e1070000     | dec                 eax
            //   33d2                 | mov                 ecx, edi
            //   41b803010000         | je                  0xd840

        $sequence_6 = { 488d9424b0150000 488bcf ff15???????? 85c0 8903 0f8494540000 }
            // n = 6, score = 200
            //   488d9424b0150000     | dec                 eax
            //   488bcf               | mov                 ecx, ebp
            //   ff15????????         |                     
            //   85c0                 | je                  0xbb98
            //   8903                 | mov                 eax, dword ptr [esp + 0x30]
            //   0f8494540000         | dec                 eax

        $sequence_7 = { 033485c0e54200 8b45e4 8b00 8906 }
            // n = 4, score = 200
            //   033485c0e54200       | add                 eax, dword ptr [edx*4 + 0x42e5c0]
            //   8b45e4               | jmp                 7
            //   8b00                 | test                byte ptr [eax + 4], 0x20
            //   8906                 | je                  0x1c

        $sequence_8 = { 4883c201 4983e901 0f853ffeffff 488d9424b0150000 488bcf }
            // n = 5, score = 200
            //   4883c201             | dec                 eax
            //   4983e901             | add                 edx, 1
            //   0f853ffeffff         | dec                 ecx
            //   488d9424b0150000     | sub                 ecx, 1
            //   488bcf               | jne                 0xfffffe45

        $sequence_9 = { 4c8d1d0dca0100 498bcc 498bd3 0fb602 4883c201 84c0 }
            // n = 6, score = 200
            //   4c8d1d0dca0100       | jmp                 0x55
            //   498bcc               | mov                 byte ptr [edx], 0x2a
            //   498bd3               | jmp                 0x50
            //   0fb602               | mov                 byte ptr [edx], 0x26
            //   4883c201             | jmp                 0x50
            //   84c0                 | mov                 byte ptr [edx], 0x5b

        $sequence_10 = { 03c1 1bc9 0bc1 59 e9???????? e8???????? ff742404 }
            // n = 7, score = 200
            //   03c1                 | add                 esi, dword ptr [eax*4 + 0x42e5c0]
            //   1bc9                 | mov                 dword ptr [ebp - 0x1c], 1
            //   0bc1                 | xor                 ebx, ebx
            //   59                   | cmp                 dword ptr [esi + 8], ebx
            //   e9????????           |                     
            //   e8????????           |                     
            //   ff742404             | add                 esi, dword ptr [eax*4 + 0x42e5c0]

        $sequence_11 = { e8???????? 4c8d0557980000 ba14030000 488bcd e8???????? }
            // n = 5, score = 200
            //   e8????????           |                     
            //   4c8d0557980000       | dec                 esp
            //   ba14030000           | lea                 ebx, dword ptr [0x1ca0d]
            //   488bcd               | dec                 ecx
            //   e8????????           |                     

        $sequence_12 = { eb53 c6022a eb4e c60226 eb49 c6025b }
            // n = 6, score = 200
            //   eb53                 | mov                 eax, dword ptr [esp + 0x30]
            //   c6022a               | dec                 eax
            //   eb4e                 | lea                 ecx, dword ptr [esp + 0x7e1]
            //   c60226               | xor                 edx, edx
            //   eb49                 | inc                 ecx
            //   c6025b               | mov                 eax, 0x103

        $sequence_13 = { 030495c0e54200 eb05 b8???????? f6400420 }
            // n = 4, score = 200
            //   030495c0e54200       | jne                 0xfffffe45
            //   eb05                 | dec                 eax
            //   b8????????           |                     
            //   f6400420             | lea                 edx, dword ptr [esp + 0x4be0]

        $sequence_14 = { 03ce c6840c3801000000 8d8424a05c0000 33f6 }
            // n = 4, score = 200
            //   03ce                 | add                 esi, dword ptr [eax*4 + 0x42e5c0]
            //   c6840c3801000000     | mov                 dword ptr [ebp - 0x1c], 1
            //   8d8424a05c0000       | xor                 ebx, ebx
            //   33f6                 | cmp                 dword ptr [esi + 8], ebx

        $sequence_15 = { 4885c9 7415 6690 410fb6440bff 4883e901 88840cd0390000 }
            // n = 6, score = 200
            //   4885c9               | dec                 eax
            //   7415                 | add                 edx, 1
            //   6690                 | test                al, al
            //   410fb6440bff         | dec                 esp
            //   4883e901             | lea                 eax, dword ptr [0x9857]
            //   88840cd0390000       | mov                 edx, 0x314

    condition:
        7 of them and filesize < 434176
}