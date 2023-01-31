rule win_adylkuzz_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.adylkuzz."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.adylkuzz"
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
        $sequence_0 = { f5 c1c803 66f7c6390e 6685d2 f8 8d805a91c299 33d8 }
            // n = 7, score = 100
            //   f5                   | cmc                 
            //   c1c803               | ror                 eax, 3
            //   66f7c6390e           | test                si, 0xe39
            //   6685d2               | test                dx, dx
            //   f8                   | clc                 
            //   8d805a91c299         | lea                 eax, [eax - 0x663d6ea6]
            //   33d8                 | xor                 ebx, eax

        $sequence_1 = { e8???????? 83c018 891c24 89442404 e8???????? 83c414 5b }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c018               | add                 eax, 0x18
            //   891c24               | mov                 dword ptr [esp], ebx
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   5b                   | pop                 ebx

        $sequence_2 = { f8 d1c0 48 33d8 81ed04000000 3bd8 6685d5 }
            // n = 7, score = 100
            //   f8                   | clc                 
            //   d1c0                 | rol                 eax, 1
            //   48                   | dec                 eax
            //   33d8                 | xor                 ebx, eax
            //   81ed04000000         | sub                 ebp, 4
            //   3bd8                 | cmp                 ebx, eax
            //   6685d5               | test                bp, dx

        $sequence_3 = { f7d8 f5 81fbec10f429 8d80aab4f1e0 f5 f9 6681ff262c }
            // n = 7, score = 100
            //   f7d8                 | neg                 eax
            //   f5                   | cmc                 
            //   81fbec10f429         | cmp                 ebx, 0x29f410ec
            //   8d80aab4f1e0         | lea                 eax, [eax - 0x1f0e4b56]
            //   f5                   | cmc                 
            //   f9                   | stc                 
            //   6681ff262c           | cmp                 di, 0x2c26

        $sequence_4 = { f7d9 5d 0f96c5 80f1b9 8da42408000000 6633ce d2ed }
            // n = 7, score = 100
            //   f7d9                 | neg                 ecx
            //   5d                   | pop                 ebp
            //   0f96c5               | setbe               ch
            //   80f1b9               | xor                 cl, 0xb9
            //   8da42408000000       | lea                 esp, [esp + 8]
            //   6633ce               | xor                 cx, si
            //   d2ed                 | shr                 ch, cl

        $sequence_5 = { e8???????? 89442434 89d8 e8???????? 8944241c eb2a c744241c00000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   89442434             | mov                 dword ptr [esp + 0x34], eax
            //   89d8                 | mov                 eax, ebx
            //   e8????????           |                     
            //   8944241c             | mov                 dword ptr [esp + 0x1c], eax
            //   eb2a                 | jmp                 0x2c
            //   c744241c00000000     | mov                 dword ptr [esp + 0x1c], 0

        $sequence_6 = { e8???????? 8b842474020000 83fe63 8d5001 89942474020000 c6005c 7711 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b842474020000       | mov                 eax, dword ptr [esp + 0x274]
            //   83fe63               | cmp                 esi, 0x63
            //   8d5001               | lea                 edx, [eax + 1]
            //   89942474020000       | mov                 dword ptr [esp + 0x274], edx
            //   c6005c               | mov                 byte ptr [eax], 0x5c
            //   7711                 | ja                  0x13

        $sequence_7 = { f5 f7d0 33d8 f9 03f8 ffe7 668b442500 }
            // n = 7, score = 100
            //   f5                   | cmc                 
            //   f7d0                 | not                 eax
            //   33d8                 | xor                 ebx, eax
            //   f9                   | stc                 
            //   03f8                 | add                 edi, eax
            //   ffe7                 | jmp                 edi
            //   668b442500           | mov                 ax, word ptr [ebp]

        $sequence_8 = { e8???????? 8b462c b9???????? 034630 89fa 890424 89d8 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b462c               | mov                 eax, dword ptr [esi + 0x2c]
            //   b9????????           |                     
            //   034630               | add                 eax, dword ptr [esi + 0x30]
            //   89fa                 | mov                 edx, edi
            //   890424               | mov                 dword ptr [esp], eax
            //   89d8                 | mov                 eax, ebx

        $sequence_9 = { f7c2d9394e71 33c3 8d80bff55da3 f7d0 2d064cd540 c1c002 f8 }
            // n = 7, score = 100
            //   f7c2d9394e71         | test                edx, 0x714e39d9
            //   33c3                 | xor                 eax, ebx
            //   8d80bff55da3         | lea                 eax, [eax - 0x5ca20a41]
            //   f7d0                 | not                 eax
            //   2d064cd540           | sub                 eax, 0x40d54c06
            //   c1c002               | rol                 eax, 2
            //   f8                   | clc                 

    condition:
        7 of them and filesize < 6438912
}