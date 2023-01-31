rule win_stegoloader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.stegoloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stegoloader"
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
        $sequence_0 = { 85d2 7e68 8b4d0c 8b4508 53 }
            // n = 5, score = 200
            //   85d2                 | test                edx, edx
            //   7e68                 | jle                 0x6a
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   53                   | push                ebx

        $sequence_1 = { c645fd58 c645fe58 885dff ff15???????? 85c0 7451 }
            // n = 6, score = 200
            //   c645fd58             | mov                 byte ptr [ebp - 3], 0x58
            //   c645fe58             | mov                 byte ptr [ebp - 2], 0x58
            //   885dff               | mov                 byte ptr [ebp - 1], bl
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7451                 | je                  0x53

        $sequence_2 = { c645e353 c645e459 c645e553 c645e654 c645e745 }
            // n = 5, score = 200
            //   c645e353             | mov                 byte ptr [ebp - 0x1d], 0x53
            //   c645e459             | mov                 byte ptr [ebp - 0x1c], 0x59
            //   c645e553             | mov                 byte ptr [ebp - 0x1b], 0x53
            //   c645e654             | mov                 byte ptr [ebp - 0x1a], 0x54
            //   c645e745             | mov                 byte ptr [ebp - 0x19], 0x45

        $sequence_3 = { 894c2408 e9???????? e8???????? 85f6 }
            // n = 4, score = 200
            //   894c2408             | mov                 dword ptr [esp + 8], ecx
            //   e9????????           |                     
            //   e8????????           |                     
            //   85f6                 | test                esi, esi

        $sequence_4 = { 8b01 6a01 ff5008 8365f400 8bce }
            // n = 5, score = 200
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   6a01                 | push                1
            //   ff5008               | call                dword ptr [eax + 8]
            //   8365f400             | and                 dword ptr [ebp - 0xc], 0
            //   8bce                 | mov                 ecx, esi

        $sequence_5 = { 662b5e10 0fb7c3 8b4e1c 0fb7c0 8d0481 8b0438 03c7 }
            // n = 7, score = 200
            //   662b5e10             | sub                 bx, word ptr [esi + 0x10]
            //   0fb7c3               | movzx               eax, bx
            //   8b4e1c               | mov                 ecx, dword ptr [esi + 0x1c]
            //   0fb7c0               | movzx               eax, ax
            //   8d0481               | lea                 eax, [ecx + eax*4]
            //   8b0438               | mov                 eax, dword ptr [eax + edi]
            //   03c7                 | add                 eax, edi

        $sequence_6 = { 88840df0feffff 0fb645ff 3bc2 889c0df1feffff 72de }
            // n = 5, score = 200
            //   88840df0feffff       | mov                 byte ptr [ebp + ecx - 0x110], al
            //   0fb645ff             | movzx               eax, byte ptr [ebp - 1]
            //   3bc2                 | cmp                 eax, edx
            //   889c0df1feffff       | mov                 byte ptr [ebp + ecx - 0x10f], bl
            //   72de                 | jb                  0xffffffe0

        $sequence_7 = { 8365f800 43 8b4d08 e8???????? }
            // n = 4, score = 200
            //   8365f800             | and                 dword ptr [ebp - 8], 0
            //   43                   | inc                 ebx
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   e8????????           |                     

        $sequence_8 = { 8b4004 6a40 8945f8 6800300000 8d45f8 }
            // n = 5, score = 200
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   6a40                 | push                0x40
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   6800300000           | push                0x3000
            //   8d45f8               | lea                 eax, [ebp - 8]

        $sequence_9 = { eb09 8bce 8b06 6a01 ff5008 5e }
            // n = 6, score = 200
            //   eb09                 | jmp                 0xb
            //   8bce                 | mov                 ecx, esi
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   6a01                 | push                1
            //   ff5008               | call                dword ptr [eax + 8]
            //   5e                   | pop                 esi

        $sequence_10 = { 8b043e 83c604 85c0 7612 8bd0 }
            // n = 5, score = 200
            //   8b043e               | mov                 eax, dword ptr [esi + edi]
            //   83c604               | add                 esi, 4
            //   85c0                 | test                eax, eax
            //   7612                 | jbe                 0x14
            //   8bd0                 | mov                 edx, eax

        $sequence_11 = { 84c0 7409 8b4508 8930 b301 }
            // n = 5, score = 200
            //   84c0                 | test                al, al
            //   7409                 | je                  0xb
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8930                 | mov                 dword ptr [eax], esi
            //   b301                 | mov                 bl, 1

        $sequence_12 = { 83c604 4a 75f0 8a043e 46 84c0 }
            // n = 6, score = 200
            //   83c604               | add                 esi, 4
            //   4a                   | dec                 edx
            //   75f0                 | jne                 0xfffffff2
            //   8a043e               | mov                 al, byte ptr [esi + edi]
            //   46                   | inc                 esi
            //   84c0                 | test                al, al

        $sequence_13 = { 8b7508 8bc6 5e 5b }
            // n = 4, score = 200
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_14 = { 8bf0 8975f8 eb07 8365f800 8b75f8 85f6 0f84cb000000 }
            // n = 7, score = 200
            //   8bf0                 | mov                 esi, eax
            //   8975f8               | mov                 dword ptr [ebp - 8], esi
            //   eb07                 | jmp                 9
            //   8365f800             | and                 dword ptr [ebp - 8], 0
            //   8b75f8               | mov                 esi, dword ptr [ebp - 8]
            //   85f6                 | test                esi, esi
            //   0f84cb000000         | je                  0xd1

        $sequence_15 = { 3b4508 59 59 7422 43 3b5e14 }
            // n = 6, score = 200
            //   3b4508               | cmp                 eax, dword ptr [ebp + 8]
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   7422                 | je                  0x24
            //   43                   | inc                 ebx
            //   3b5e14               | cmp                 ebx, dword ptr [esi + 0x14]

    condition:
        7 of them and filesize < 802816
}