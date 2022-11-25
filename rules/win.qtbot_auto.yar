rule win_qtbot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.qtbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.qtbot"
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
        $sequence_0 = { 85c0 742a 8b049a 03c6 50 e8???????? }
            // n = 6, score = 200
            //   85c0                 | test                eax, eax
            //   742a                 | je                  0x2c
            //   8b049a               | mov                 eax, dword ptr [edx + ebx*4]
            //   03c6                 | add                 eax, esi
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_1 = { 0fb6c9 8a8c0dfcfeffff 3008 40 89450c 83ef01 75b1 }
            // n = 7, score = 200
            //   0fb6c9               | movzx               ecx, cl
            //   8a8c0dfcfeffff       | mov                 cl, byte ptr [ebp + ecx - 0x104]
            //   3008                 | xor                 byte ptr [eax], cl
            //   40                   | inc                 eax
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   83ef01               | sub                 edi, 1
            //   75b1                 | jne                 0xffffffb3

        $sequence_2 = { 8b400c 8b7014 ad 8b00 8b4010 }
            // n = 5, score = 200
            //   8b400c               | mov                 eax, dword ptr [eax + 0xc]
            //   8b7014               | mov                 esi, dword ptr [eax + 0x14]
            //   ad                   | lodsd               eax, dword ptr [esi]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8b4010               | mov                 eax, dword ptr [eax + 0x10]

        $sequence_3 = { 8a8435fcfeffff 88841dfcfeffff 889435fcfeffff 0fb68c1dfcfeffff 0fb6c2 03c8 8b450c }
            // n = 7, score = 200
            //   8a8435fcfeffff       | mov                 al, byte ptr [ebp + esi - 0x104]
            //   88841dfcfeffff       | mov                 byte ptr [ebp + ebx - 0x104], al
            //   889435fcfeffff       | mov                 byte ptr [ebp + esi - 0x104], dl
            //   0fb68c1dfcfeffff     | movzx               ecx, byte ptr [ebp + ebx - 0x104]
            //   0fb6c2               | movzx               eax, dl
            //   03c8                 | add                 ecx, eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_4 = { 03c1 25ffffff00 42 8a1a 84db 75e9 }
            // n = 6, score = 200
            //   03c1                 | add                 eax, ecx
            //   25ffffff00           | and                 eax, 0xffffff
            //   42                   | inc                 edx
            //   8a1a                 | mov                 bl, byte ptr [edx]
            //   84db                 | test                bl, bl
            //   75e9                 | jne                 0xffffffeb

        $sequence_5 = { 8b4510 89450c 8d4301 0fb6d8 8a941dfcfeffff }
            // n = 5, score = 200
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   8d4301               | lea                 eax, [ebx + 1]
            //   0fb6d8               | movzx               ebx, al
            //   8a941dfcfeffff       | mov                 dl, byte ptr [ebp + ebx - 0x104]

        $sequence_6 = { 03c8 8b450c 0fb6c9 8a8c0dfcfeffff }
            // n = 4, score = 200
            //   03c8                 | add                 ecx, eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   0fb6c9               | movzx               ecx, cl
            //   8a8c0dfcfeffff       | mov                 cl, byte ptr [ebp + ecx - 0x104]

        $sequence_7 = { 53 8a1a 6bc80d 0fb6c3 83c0d0 }
            // n = 5, score = 200
            //   53                   | push                ebx
            //   8a1a                 | mov                 bl, byte ptr [edx]
            //   6bc80d               | imul                ecx, eax, 0xd
            //   0fb6c3               | movzx               eax, bl
            //   83c0d0               | add                 eax, -0x30

        $sequence_8 = { 0f872affffff 0fb6805a210010 ff2485f6200010 8b8614080000 3b45f4 7e03 }
            // n = 6, score = 100
            //   0f872affffff         | ja                  0xffffff30
            //   0fb6805a210010       | movzx               eax, byte ptr [eax + 0x1000215a]
            //   ff2485f6200010       | jmp                 dword ptr [eax*4 + 0x100020f6]
            //   8b8614080000         | mov                 eax, dword ptr [esi + 0x814]
            //   3b45f4               | cmp                 eax, dword ptr [ebp - 0xc]
            //   7e03                 | jle                 5

        $sequence_9 = { e8???????? 59 837e04ff 8bd8 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   837e04ff             | cmp                 dword ptr [esi + 4], -1
            //   8bd8                 | mov                 ebx, eax

        $sequence_10 = { 50 53 6a00 6a00 ff15???????? 833e05 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   53                   | push                ebx
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   833e05               | cmp                 dword ptr [esi], 5

        $sequence_11 = { 0f8781000000 ff248dfb240010 881f eb76 ff30 eb63 57 }
            // n = 7, score = 100
            //   0f8781000000         | ja                  0x87
            //   ff248dfb240010       | jmp                 dword ptr [ecx*4 + 0x100024fb]
            //   881f                 | mov                 byte ptr [edi], bl
            //   eb76                 | jmp                 0x78
            //   ff30                 | push                dword ptr [eax]
            //   eb63                 | jmp                 0x65
            //   57                   | push                edi

        $sequence_12 = { 8b0c855c300010 c1e705 33d2 03fe 42 837dfcff }
            // n = 6, score = 100
            //   8b0c855c300010       | mov                 ecx, dword ptr [eax*4 + 0x1000305c]
            //   c1e705               | shl                 edi, 5
            //   33d2                 | xor                 edx, edx
            //   03fe                 | add                 edi, esi
            //   42                   | inc                 edx
            //   837dfcff             | cmp                 dword ptr [ebp - 4], -1

        $sequence_13 = { 833e05 7521 6a10 6a40 ff15???????? 50 89461c }
            // n = 7, score = 100
            //   833e05               | cmp                 dword ptr [esi], 5
            //   7521                 | jne                 0x23
            //   6a10                 | push                0x10
            //   6a40                 | push                0x40
            //   ff15????????         |                     
            //   50                   | push                eax
            //   89461c               | mov                 dword ptr [esi + 0x1c], eax

        $sequence_14 = { 53 ff15???????? 837c241000 7423 8b442418 }
            // n = 5, score = 100
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   837c241000           | cmp                 dword ptr [esp + 0x10], 0
            //   7423                 | je                  0x25
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]

        $sequence_15 = { 8b06 83661c00 83f807 0f87c7000000 ff24857e230010 832700 e9???????? }
            // n = 7, score = 100
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   83661c00             | and                 dword ptr [esi + 0x1c], 0
            //   83f807               | cmp                 eax, 7
            //   0f87c7000000         | ja                  0xcd
            //   ff24857e230010       | jmp                 dword ptr [eax*4 + 0x1000237e]
            //   832700               | and                 dword ptr [edi], 0
            //   e9????????           |                     

    condition:
        7 of them and filesize < 57344
}