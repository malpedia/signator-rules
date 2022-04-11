rule win_starcruft_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.starcruft."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.starcruft"
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
        $sequence_0 = { c705????????02000000 c705????????47000000 c705????????00000000 c705????????00000000 c705????????00000000 c705????????00000000 6a00 }
            // n = 7, score = 100
            //   c705????????02000000     |     
            //   c705????????47000000     |     
            //   c705????????00000000     |     
            //   c705????????00000000     |     
            //   c705????????00000000     |     
            //   c705????????00000000     |     
            //   6a00                 | push                0

        $sequence_1 = { 8b45f0 8945f8 eb09 8b4df8 83c102 894df8 }
            // n = 6, score = 100
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   eb09                 | jmp                 0xb
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   83c102               | add                 ecx, 2
            //   894df8               | mov                 dword ptr [ebp - 8], ecx

        $sequence_2 = { 8945f0 8b55f0 3355f4 3355fc 0355ec 8b45f8 8d8c10f87ca21f }
            // n = 7, score = 100
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   3355f4               | xor                 edx, dword ptr [ebp - 0xc]
            //   3355fc               | xor                 edx, dword ptr [ebp - 4]
            //   0355ec               | add                 edx, dword ptr [ebp - 0x14]
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8d8c10f87ca21f       | lea                 ecx, dword ptr [eax + edx + 0x1fa27cf8]

        $sequence_3 = { 50 8d8dacfbffff 51 6a15 8d9550feffff 52 e8???????? }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d8dacfbffff         | lea                 ecx, dword ptr [ebp - 0x454]
            //   51                   | push                ecx
            //   6a15                 | push                0x15
            //   8d9550feffff         | lea                 edx, dword ptr [ebp - 0x1b0]
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_4 = { 83c410 c785d4feffff01000000 e9???????? 8d55f0 52 8d85d0feffff 50 }
            // n = 7, score = 100
            //   83c410               | add                 esp, 0x10
            //   c785d4feffff01000000     | mov    dword ptr [ebp - 0x12c], 1
            //   e9????????           |                     
            //   8d55f0               | lea                 edx, dword ptr [ebp - 0x10]
            //   52                   | push                edx
            //   8d85d0feffff         | lea                 eax, dword ptr [ebp - 0x130]
            //   50                   | push                eax

        $sequence_5 = { c685d6faffff3d c685d7faffffd3 c685d8faffffdc c685d9faffff11 c685dafaffffc0 c685dbfaffff53 }
            // n = 6, score = 100
            //   c685d6faffff3d       | mov                 byte ptr [ebp - 0x52a], 0x3d
            //   c685d7faffffd3       | mov                 byte ptr [ebp - 0x529], 0xd3
            //   c685d8faffffdc       | mov                 byte ptr [ebp - 0x528], 0xdc
            //   c685d9faffff11       | mov                 byte ptr [ebp - 0x527], 0x11
            //   c685dafaffffc0       | mov                 byte ptr [ebp - 0x526], 0xc0
            //   c685dbfaffff53       | mov                 byte ptr [ebp - 0x525], 0x53

        $sequence_6 = { 56 e8???????? 8bc6 c1f805 8b0485e0fa2e00 83e61f c1e606 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   e8????????           |                     
            //   8bc6                 | mov                 eax, esi
            //   c1f805               | sar                 eax, 5
            //   8b0485e0fa2e00       | mov                 eax, dword ptr [eax*4 + 0x2efae0]
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6

        $sequence_7 = { 668945de 8d45f4 50 e8???????? 83c404 668945e0 8b4dd4 }
            // n = 7, score = 100
            //   668945de             | mov                 word ptr [ebp - 0x22], ax
            //   8d45f4               | lea                 eax, dword ptr [ebp - 0xc]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   668945e0             | mov                 word ptr [ebp - 0x20], ax
            //   8b4dd4               | mov                 ecx, dword ptr [ebp - 0x2c]

        $sequence_8 = { 8d3c8de0fa2e00 8bf0 83e61f c1e606 8b0f 0fbe4c0e04 }
            // n = 6, score = 100
            //   8d3c8de0fa2e00       | lea                 edi, dword ptr [ecx*4 + 0x2efae0]
            //   8bf0                 | mov                 esi, eax
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   0fbe4c0e04           | movsx               ecx, byte ptr [esi + ecx + 4]

        $sequence_9 = { ff15???????? 8d85a0edffff 50 8d8de0fdffff 51 68???????? }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   8d85a0edffff         | lea                 eax, dword ptr [ebp - 0x1260]
            //   50                   | push                eax
            //   8d8de0fdffff         | lea                 ecx, dword ptr [ebp - 0x220]
            //   51                   | push                ecx
            //   68????????           |                     

    condition:
        7 of them and filesize < 294912
}