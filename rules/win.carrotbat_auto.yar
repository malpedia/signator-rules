rule win_carrotbat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.carrotbat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.carrotbat"
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
        $sequence_0 = { 83e01f c1fa05 8b149520ee4000 59 c1e006 59 8a4dff }
            // n = 7, score = 100
            //   83e01f               | and                 eax, 0x1f
            //   c1fa05               | sar                 edx, 5
            //   8b149520ee4000       | mov                 edx, dword ptr [edx*4 + 0x40ee20]
            //   59                   | pop                 ecx
            //   c1e006               | shl                 eax, 6
            //   59                   | pop                 ecx
            //   8a4dff               | mov                 cl, byte ptr [ebp - 1]

        $sequence_1 = { 57 33ff ffb7d0d64000 ff15???????? }
            // n = 4, score = 100
            //   57                   | push                edi
            //   33ff                 | xor                 edi, edi
            //   ffb7d0d64000         | push                dword ptr [edi + 0x40d6d0]
            //   ff15????????         |                     

        $sequence_2 = { 85c9 7e0f 8a1c3a 889c1001ed4000 42 }
            // n = 5, score = 100
            //   85c9                 | test                ecx, ecx
            //   7e0f                 | jle                 0x11
            //   8a1c3a               | mov                 bl, byte ptr [edx + edi]
            //   889c1001ed4000       | mov                 byte ptr [eax + edx + 0x40ed01], bl
            //   42                   | inc                 edx

        $sequence_3 = { c1f805 8b048520ee4000 83e61f c1e606 8d443004 8020fe }
            // n = 6, score = 100
            //   c1f805               | sar                 eax, 5
            //   8b048520ee4000       | mov                 eax, dword ptr [eax*4 + 0x40ee20]
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   8d443004             | lea                 eax, dword ptr [eax + esi + 4]
            //   8020fe               | and                 byte ptr [eax], 0xfe

        $sequence_4 = { e8???????? 59 897dfc 897dd8 83ff40 0f8d3b010000 8b34bd20ee4000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   897dd8               | mov                 dword ptr [ebp - 0x28], edi
            //   83ff40               | cmp                 edi, 0x40
            //   0f8d3b010000         | jge                 0x141
            //   8b34bd20ee4000       | mov                 esi, dword ptr [edi*4 + 0x40ee20]

        $sequence_5 = { c1e006 8b0c8d20ee4000 8d440104 8020fe ff36 }
            // n = 5, score = 100
            //   c1e006               | shl                 eax, 6
            //   8b0c8d20ee4000       | mov                 ecx, dword ptr [ecx*4 + 0x40ee20]
            //   8d440104             | lea                 eax, dword ptr [ecx + eax + 4]
            //   8020fe               | and                 byte ptr [eax], 0xfe
            //   ff36                 | push                dword ptr [esi]

        $sequence_6 = { 660fb6cb 893424 0fc9 f6d5 }
            // n = 4, score = 100
            //   660fb6cb             | movzx               cx, bl
            //   893424               | mov                 dword ptr [esp], esi
            //   0fc9                 | bswap               ecx
            //   f6d5                 | not                 ch

        $sequence_7 = { a3???????? 33c0 c3 8bff 55 8bec b8e41a0000 }
            // n = 7, score = 100
            //   a3????????           |                     
            //   33c0                 | xor                 eax, eax
            //   c3                   | ret                 
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   b8e41a0000           | mov                 eax, 0x1ae4

        $sequence_8 = { 53 c7042405000000 e8???????? ff35???????? 8f442434 9c }
            // n = 6, score = 100
            //   53                   | push                ebx
            //   c7042405000000       | mov                 dword ptr [esp], 5
            //   e8????????           |                     
            //   ff35????????         |                     
            //   8f442434             | pop                 dword ptr [esp + 0x34]
            //   9c                   | pushfd              

        $sequence_9 = { 7e15 8dbc0101ed4000 8b5d0c 8a1c1e }
            // n = 4, score = 100
            //   7e15                 | jle                 0x17
            //   8dbc0101ed4000       | lea                 edi, dword ptr [ecx + eax + 0x40ed01]
            //   8b5d0c               | mov                 ebx, dword ptr [ebp + 0xc]
            //   8a1c1e               | mov                 bl, byte ptr [esi + ebx]

    condition:
        7 of them and filesize < 360448
}