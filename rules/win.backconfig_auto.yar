rule win_backconfig_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.backconfig."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.backconfig"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
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
        $sequence_0 = { 50 c745f498e14000 e8???????? cc 8bff 55 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   c745f498e14000       | mov                 dword ptr [ebp - 0xc], 0x40e198
            //   e8????????           |                     
            //   cc                   | int3                
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp

        $sequence_1 = { 8d8d58ffffff 51 50 ff15???????? 6a00 6800008000 68???????? }
            // n = 7, score = 100
            //   8d8d58ffffff         | lea                 ecx, [ebp - 0xa8]
            //   51                   | push                ecx
            //   50                   | push                eax
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6800008000           | push                0x800000
            //   68????????           |                     

        $sequence_2 = { 75f9 2bc6 3bc8 72e1 6a00 }
            // n = 5, score = 100
            //   75f9                 | jne                 0xfffffffb
            //   2bc6                 | sub                 eax, esi
            //   3bc8                 | cmp                 ecx, eax
            //   72e1                 | jb                  0xffffffe3
            //   6a00                 | push                0

        $sequence_3 = { 817de080e14000 7311 8b45e0 8b00 85c0 }
            // n = 5, score = 100
            //   817de080e14000       | cmp                 dword ptr [ebp - 0x20], 0x40e180
            //   7311                 | jae                 0x13
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   85c0                 | test                eax, eax

        $sequence_4 = { 0f8d3b010000 8b34bdc0504100 85f6 0f84b9000000 8975e0 }
            // n = 5, score = 100
            //   0f8d3b010000         | jge                 0x141
            //   8b34bdc0504100       | mov                 esi, dword ptr [edi*4 + 0x4150c0]
            //   85f6                 | test                esi, esi
            //   0f84b9000000         | je                  0xbf
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi

        $sequence_5 = { 8d34c550224100 833e00 7513 50 e8???????? 59 85c0 }
            // n = 7, score = 100
            //   8d34c550224100       | lea                 esi, [eax*8 + 0x412250]
            //   833e00               | cmp                 dword ptr [esi], 0
            //   7513                 | jne                 0x15
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax

        $sequence_6 = { 83e61f c1e606 033485c0504100 c745e401000000 33db }
            // n = 5, score = 100
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   033485c0504100       | add                 esi, dword ptr [eax*4 + 0x4150c0]
            //   c745e401000000       | mov                 dword ptr [ebp - 0x1c], 1
            //   33db                 | xor                 ebx, ebx

        $sequence_7 = { c1f805 8d1485c0504100 8b0a 83e61f c1e606 03ce }
            // n = 6, score = 100
            //   c1f805               | sar                 eax, 5
            //   8d1485c0504100       | lea                 edx, [eax*4 + 0x4150c0]
            //   8b0a                 | mov                 ecx, dword ptr [edx]
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   03ce                 | add                 ecx, esi

        $sequence_8 = { 7229 f3a5 ff249530714000 8bc7 ba03000000 83e904 }
            // n = 6, score = 100
            //   7229                 | jb                  0x2b
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   ff249530714000       | jmp                 dword ptr [edx*4 + 0x407130]
            //   8bc7                 | mov                 eax, edi
            //   ba03000000           | mov                 edx, 3
            //   83e904               | sub                 ecx, 4

        $sequence_9 = { ebd5 8bc8 c1f905 8b0c8dc0504100 83e01f }
            // n = 5, score = 100
            //   ebd5                 | jmp                 0xffffffd7
            //   8bc8                 | mov                 ecx, eax
            //   c1f905               | sar                 ecx, 5
            //   8b0c8dc0504100       | mov                 ecx, dword ptr [ecx*4 + 0x4150c0]
            //   83e01f               | and                 eax, 0x1f

    condition:
        7 of them and filesize < 217088
}