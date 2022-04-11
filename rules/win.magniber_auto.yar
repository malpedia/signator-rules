rule win_magniber_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.magniber."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.magniber"
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
        $sequence_0 = { 66890a 8b45f8 83c002 8945f8 b92a000000 }
            // n = 5, score = 400
            //   66890a               | mov                 word ptr [edx], cx
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   83c002               | add                 eax, 2
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   b92a000000           | mov                 ecx, 0x2a

        $sequence_1 = { 85c0 7502 ebb9 8b5508 52 }
            // n = 5, score = 400
            //   85c0                 | test                eax, eax
            //   7502                 | jne                 4
            //   ebb9                 | jmp                 0xffffffbb
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   52                   | push                edx

        $sequence_2 = { 8b5508 8b826c040000 50 ff15???????? 85c0 740e }
            // n = 6, score = 400
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b826c040000         | mov                 eax, dword ptr [edx + 0x46c]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   740e                 | je                  0x10

        $sequence_3 = { c7856cffffffc09e4000 c78570ffffffc89e4000 c78574ffffffd09e4000 c78578ffffffd89e4000 c7857cffffffe09e4000 c74580e89e4000 }
            // n = 6, score = 400
            //   c7856cffffffc09e4000     | mov    dword ptr [ebp - 0x94], 0x409ec0
            //   c78570ffffffc89e4000     | mov    dword ptr [ebp - 0x90], 0x409ec8
            //   c78574ffffffd09e4000     | mov    dword ptr [ebp - 0x8c], 0x409ed0
            //   c78578ffffffd89e4000     | mov    dword ptr [ebp - 0x88], 0x409ed8
            //   c7857cffffffe09e4000     | mov    dword ptr [ebp - 0x84], 0x409ee0
            //   c74580e89e4000       | mov                 dword ptr [ebp - 0x80], 0x409ee8

        $sequence_4 = { 6a7a 6a61 e8???????? 83c408 8b4dfc }
            // n = 5, score = 400
            //   6a7a                 | push                0x7a
            //   6a61                 | push                0x61
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_5 = { ba65000000 668955ee b878000000 668945f0 b965000000 }
            // n = 5, score = 400
            //   ba65000000           | mov                 edx, 0x65
            //   668955ee             | mov                 word ptr [ebp - 0x12], dx
            //   b878000000           | mov                 eax, 0x78
            //   668945f0             | mov                 word ptr [ebp - 0x10], ax
            //   b965000000           | mov                 ecx, 0x65

        $sequence_6 = { 83c408 6804010000 8d859cfdffff 50 }
            // n = 4, score = 400
            //   83c408               | add                 esp, 8
            //   6804010000           | push                0x104
            //   8d859cfdffff         | lea                 eax, dword ptr [ebp - 0x264]
            //   50                   | push                eax

        $sequence_7 = { ba63000000 668955b2 b820000000 668945b4 b970000000 66894db6 ba69000000 }
            // n = 7, score = 400
            //   ba63000000           | mov                 edx, 0x63
            //   668955b2             | mov                 word ptr [ebp - 0x4e], dx
            //   b820000000           | mov                 eax, 0x20
            //   668945b4             | mov                 word ptr [ebp - 0x4c], ax
            //   b970000000           | mov                 ecx, 0x70
            //   66894db6             | mov                 word ptr [ebp - 0x4a], cx
            //   ba69000000           | mov                 edx, 0x69

        $sequence_8 = { ba63000000 668955b2 b820000000 668945b4 b970000000 66894db6 }
            // n = 6, score = 400
            //   ba63000000           | mov                 edx, 0x63
            //   668955b2             | mov                 word ptr [ebp - 0x4e], dx
            //   b820000000           | mov                 eax, 0x20
            //   668945b4             | mov                 word ptr [ebp - 0x4c], ax
            //   b970000000           | mov                 ecx, 0x70
            //   66894db6             | mov                 word ptr [ebp - 0x4a], cx

        $sequence_9 = { 52 8d8554ffffff 50 8b8d24feffff 51 8d9510feffff 52 }
            // n = 7, score = 400
            //   52                   | push                edx
            //   8d8554ffffff         | lea                 eax, dword ptr [ebp - 0xac]
            //   50                   | push                eax
            //   8b8d24feffff         | mov                 ecx, dword ptr [ebp - 0x1dc]
            //   51                   | push                ecx
            //   8d9510feffff         | lea                 edx, dword ptr [ebp - 0x1f0]
            //   52                   | push                edx

    condition:
        7 of them and filesize < 114688
}