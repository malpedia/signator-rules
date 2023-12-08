rule win_nightsky_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.nightsky."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nightsky"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
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
        $sequence_0 = { 420fb68c1210ab0400 c1e108 0bc8 420fb6841212ab0400 }
            // n = 4, score = 100
            //   420fb68c1210ab0400     | push    ebp
            //   c1e108               | dec                 ecx
            //   0bc8                 | movsx               eax, sp
            //   420fb6841212ab0400     | pushfd    

        $sequence_1 = { 4150 4d0fabe0 66442bc5 311424 6641d3e0 4158 4863d2 }
            // n = 7, score = 100
            //   4150                 | dec                 ecx
            //   4d0fabe0             | add                 ecx, 4
            //   66442bc5             | ret                 
            //   311424               | inc                 eax
            //   6641d3e0             | push                edi
            //   4158                 | dec                 eax
            //   4863d2               | sub                 esp, 0x20

        $sequence_2 = { 4883ec48 488364243000 8364242800 41b803000000 488d0dc0460000 4533c9 ba00000040 }
            // n = 7, score = 100
            //   4883ec48             | imul                esi, esi, 0x58
            //   488364243000         | jae                 0x2bc
            //   8364242800           | dec                 eax
            //   41b803000000         | mov                 esi, ebx
            //   488d0dc0460000       | dec                 esp
            //   4533c9               | mov                 esi, ebx
            //   ba00000040           | dec                 ecx

        $sequence_3 = { 5f c3 488d05cf110000 48b90000000000000080 488987c8000000 488d0557990200 }
            // n = 6, score = 100
            //   5f                   | mov                 edi, ebx
            //   c3                   | dec                 eax
            //   488d05cf110000       | add                 edi, edi
            //   48b90000000000000080     | dec    esp
            //   488987c8000000       | lea                 ebp, [0x1002d]
            //   488d0557990200       | dec                 ecx

        $sequence_4 = { e8???????? 488d15d92c0100 41b804010000 33c9 c605????????00 ff15???????? }
            // n = 6, score = 100
            //   e8????????           |                     
            //   488d15d92c0100       | and                 al, 0x80
            //   41b804010000         | dec                 esp
            //   33c9                 | mov                 esi, dword ptr [esp + 0x30]
            //   c605????????00       |                     
            //   ff15????????         |                     

        $sequence_5 = { 488d15d4be0000 41b898000000 498bd9 e8???????? 488b8424d0050000 488b9424e8050000 }
            // n = 6, score = 100
            //   488d15d4be0000       | dec                 eax
            //   41b898000000         | mov                 dword ptr [esp + 0x30], esi
            //   498bd9               | dec                 eax
            //   e8????????           |                     
            //   488b8424d0050000     | mov                 dword ptr [esp + 0x38], edi
            //   488b9424e8050000     | dec                 eax

        $sequence_6 = { e41d 1a5b5f a9b7f95f5f b8cbaa75cc d113 0ae4 }
            // n = 6, score = 100
            //   e41d                 | mov                 dword ptr [ebp - 0x10], edi
            //   1a5b5f               | mov                 eax, esi
            //   a9b7f95f5f           | dec                 eax
            //   b8cbaa75cc           | shr                 eax, 0x18
            //   d113                 | inc                 esi
            //   0ae4                 | movzx               ecx, byte ptr [ecx + esi + 0x56310]

        $sequence_7 = { 0f8c96000000 3b1d???????? 0f838a000000 488bf3 4c8be3 49c1fc05 4c8d2d7e190100 }
            // n = 7, score = 100
            //   0f8c96000000         | mov                 eax, dword ptr [ecx]
            //   3b1d????????         |                     
            //   0f838a000000         | jmp                 0x241
            //   488bf3               | dec                 eax
            //   4c8be3               | test                edi, edi
            //   49c1fc05             | jne                 0x1e5
            //   4c8d2d7e190100       | xor                 eax, eax

        $sequence_8 = { 488d0d0fda0000 480f45cf 48894b48 e8???????? eb17 4885ff 488d0dead90000 }
            // n = 7, score = 100
            //   488d0d0fda0000       | xor                 eax, esp
            //   480f45cf             | inc                 esp
            //   48894b48             | add                 eax, eax
            //   e8????????           |                     
            //   eb17                 | dec                 eax
            //   4885ff               | lea                 eax, [0x25e92]
            //   488d0dead90000       | inc                 esp

        $sequence_9 = { 4883ec28 4c8bc1 4c8d0d52bbfdff 498bc9 }
            // n = 4, score = 100
            //   4883ec28             | inc                 ebp
            //   4c8bc1               | cmp                 eax, ebx
            //   4c8d0d52bbfdff       | jl                  0x4b2
            //   498bc9               | inc                 ecx

    condition:
        7 of them and filesize < 19536896
}