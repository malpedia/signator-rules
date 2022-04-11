rule win_penco_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.penco."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.penco"
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
        $sequence_0 = { 8b9554beffff 83c201 899554beffff 8b8554beffff 3b852094ffff 7d3d 8b8d2493ffff }
            // n = 7, score = 100
            //   8b9554beffff         | mov                 edx, dword ptr [ebp - 0x41ac]
            //   83c201               | add                 edx, 1
            //   899554beffff         | mov                 dword ptr [ebp - 0x41ac], edx
            //   8b8554beffff         | mov                 eax, dword ptr [ebp - 0x41ac]
            //   3b852094ffff         | cmp                 eax, dword ptr [ebp - 0x6be0]
            //   7d3d                 | jge                 0x3f
            //   8b8d2493ffff         | mov                 ecx, dword ptr [ebp - 0x6cdc]

        $sequence_1 = { 83c408 83c314 3b01 89442418 0f8ce9feffff eb1a 50 }
            // n = 7, score = 100
            //   83c408               | add                 esp, 8
            //   83c314               | add                 ebx, 0x14
            //   3b01                 | cmp                 eax, dword ptr [ecx]
            //   89442418             | mov                 dword ptr [esp + 0x18], eax
            //   0f8ce9feffff         | jl                  0xfffffeef
            //   eb1a                 | jmp                 0x1c
            //   50                   | push                eax

        $sequence_2 = { 0f850c030000 8b742414 3bf7 0f840e030000 }
            // n = 4, score = 100
            //   0f850c030000         | jne                 0x312
            //   8b742414             | mov                 esi, dword ptr [esp + 0x14]
            //   3bf7                 | cmp                 esi, edi
            //   0f840e030000         | je                  0x314

        $sequence_3 = { e9???????? 8b450c 99 b903000000 f7f9 8d148504000000 3b5514 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   99                   | cdq                 
            //   b903000000           | mov                 ecx, 3
            //   f7f9                 | idiv                ecx
            //   8d148504000000       | lea                 edx, dword ptr [eax*4 + 4]
            //   3b5514               | cmp                 edx, dword ptr [ebp + 0x14]

        $sequence_4 = { 56 57 33f6 33ff 897dfc 3b1cfde8c33400 7409 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   33f6                 | xor                 esi, esi
            //   33ff                 | xor                 edi, edi
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   3b1cfde8c33400       | cmp                 ebx, dword ptr [edi*8 + 0x34c3e8]
            //   7409                 | je                  0xb

        $sequence_5 = { c1eb10 0fb6db 33349d28f83400 8b5c2418 c1eb18 33349d28fc3400 0fb6d9 }
            // n = 7, score = 100
            //   c1eb10               | shr                 ebx, 0x10
            //   0fb6db               | movzx               ebx, bl
            //   33349d28f83400       | xor                 esi, dword ptr [ebx*4 + 0x34f828]
            //   8b5c2418             | mov                 ebx, dword ptr [esp + 0x18]
            //   c1eb18               | shr                 ebx, 0x18
            //   33349d28fc3400       | xor                 esi, dword ptr [ebx*4 + 0x34fc28]
            //   0fb6d9               | movzx               ebx, cl

        $sequence_6 = { 46 33db 3b7500 bf80000000 0f8f2f040000 85c9 0f8eb4000000 }
            // n = 7, score = 100
            //   46                   | inc                 esi
            //   33db                 | xor                 ebx, ebx
            //   3b7500               | cmp                 esi, dword ptr [ebp]
            //   bf80000000           | mov                 edi, 0x80
            //   0f8f2f040000         | jg                  0x435
            //   85c9                 | test                ecx, ecx
            //   0f8eb4000000         | jle                 0xba

        $sequence_7 = { 8b95a8f5ffff 0395dcfdffff 3b5518 7e02 eb5c 8d85c4fdffff 50 }
            // n = 7, score = 100
            //   8b95a8f5ffff         | mov                 edx, dword ptr [ebp - 0xa58]
            //   0395dcfdffff         | add                 edx, dword ptr [ebp - 0x224]
            //   3b5518               | cmp                 edx, dword ptr [ebp + 0x18]
            //   7e02                 | jle                 4
            //   eb5c                 | jmp                 0x5e
            //   8d85c4fdffff         | lea                 eax, dword ptr [ebp - 0x23c]
            //   50                   | push                eax

        $sequence_8 = { 89542410 8b542414 03d2 89542414 e9???????? 8d8424fcd70000 }
            // n = 6, score = 100
            //   89542410             | mov                 dword ptr [esp + 0x10], edx
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   03d2                 | add                 edx, edx
            //   89542414             | mov                 dword ptr [esp + 0x14], edx
            //   e9????????           |                     
            //   8d8424fcd70000       | lea                 eax, dword ptr [esp + 0xd7fc]

        $sequence_9 = { 83c201 8995c0fdffff 8b85c0fdffff 3b85a8f0ffff 7d25 8b8dc0fdffff 0fbe940d88ecffff }
            // n = 7, score = 100
            //   83c201               | add                 edx, 1
            //   8995c0fdffff         | mov                 dword ptr [ebp - 0x240], edx
            //   8b85c0fdffff         | mov                 eax, dword ptr [ebp - 0x240]
            //   3b85a8f0ffff         | cmp                 eax, dword ptr [ebp - 0xf58]
            //   7d25                 | jge                 0x27
            //   8b8dc0fdffff         | mov                 ecx, dword ptr [ebp - 0x240]
            //   0fbe940d88ecffff     | movsx               edx, byte ptr [ebp + ecx - 0x1378]

    condition:
        7 of them and filesize < 319488
}