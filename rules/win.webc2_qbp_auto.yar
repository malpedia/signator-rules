rule win_webc2_qbp_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.webc2_qbp."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_qbp"
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
        $sequence_0 = { 7574 6800010000 6a00 8d85ecfdffff 50 e8???????? 83c40c }
            // n = 7, score = 100
            //   7574                 | jne                 0x76
            //   6800010000           | push                0x100
            //   6a00                 | push                0
            //   8d85ecfdffff         | lea                 eax, dword ptr [ebp - 0x214]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_1 = { c1e010 8b4de4 8b11 0bd0 8b45e4 8910 8b4de4 }
            // n = 7, score = 100
            //   c1e010               | shl                 eax, 0x10
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   0bd0                 | or                  edx, eax
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   8910                 | mov                 dword ptr [eax], edx
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]

        $sequence_2 = { 68???????? 8d85f8feffff 50 e8???????? 83c404 8d8c05f8feffff 038dd8fcffff }
            // n = 7, score = 100
            //   68????????           |                     
            //   8d85f8feffff         | lea                 eax, dword ptr [ebp - 0x108]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8d8c05f8feffff       | lea                 ecx, dword ptr [ebp + eax - 0x108]
            //   038dd8fcffff         | add                 ecx, dword ptr [ebp - 0x328]

        $sequence_3 = { 8b450c 83c010 8945fc 8b4dfc 51 }
            // n = 5, score = 100
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   83c010               | add                 eax, 0x10
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   51                   | push                ecx

        $sequence_4 = { 25ff000000 50 8b4de4 e8???????? 8b4de4 8b11 81e2000000ff }
            // n = 7, score = 100
            //   25ff000000           | and                 eax, 0xff
            //   50                   | push                eax
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]
            //   e8????????           |                     
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   81e2000000ff         | and                 edx, 0xff000000

        $sequence_5 = { 51 8b55ec 52 ff15???????? 8945e0 837de800 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   837de800             | cmp                 dword ptr [ebp - 0x18], 0

        $sequence_6 = { 51 ff15???????? 6a10 6a00 8d95d8fcffff 52 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   6a10                 | push                0x10
            //   6a00                 | push                0
            //   8d95d8fcffff         | lea                 edx, dword ptr [ebp - 0x328]
            //   52                   | push                edx

        $sequence_7 = { 0fbf45fc 0fbf4dfc 8b55f8 0fbf8c4a4c520000 8b55f8 8b75f8 }
            // n = 6, score = 100
            //   0fbf45fc             | movsx               eax, word ptr [ebp - 4]
            //   0fbf4dfc             | movsx               ecx, word ptr [ebp - 4]
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   0fbf8c4a4c520000     | movsx               ecx, word ptr [edx + ecx*2 + 0x524c]
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   8b75f8               | mov                 esi, dword ptr [ebp - 8]

        $sequence_8 = { 66899144100000 8b55e8 668b45f0 66898246100000 0fbf4df0 83f93c 7c02 }
            // n = 7, score = 100
            //   66899144100000       | mov                 word ptr [ecx + 0x1044], dx
            //   8b55e8               | mov                 edx, dword ptr [ebp - 0x18]
            //   668b45f0             | mov                 ax, word ptr [ebp - 0x10]
            //   66898246100000       | mov                 word ptr [edx + 0x1046], ax
            //   0fbf4df0             | movsx               ecx, word ptr [ebp - 0x10]
            //   83f93c               | cmp                 ecx, 0x3c
            //   7c02                 | jl                  4

        $sequence_9 = { e8???????? 0fbf5508 8b45ec 668b8c501c7c0000 66894d08 0fbf5508 8b45ec }
            // n = 7, score = 100
            //   e8????????           |                     
            //   0fbf5508             | movsx               edx, word ptr [ebp + 8]
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   668b8c501c7c0000     | mov                 cx, word ptr [eax + edx*2 + 0x7c1c]
            //   66894d08             | mov                 word ptr [ebp + 8], cx
            //   0fbf5508             | movsx               edx, word ptr [ebp + 8]
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]

    condition:
        7 of them and filesize < 630784
}