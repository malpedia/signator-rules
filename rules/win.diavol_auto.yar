rule win_diavol_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.diavol."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.diavol"
        malpedia_rule_date = "20220513"
        malpedia_hash = "7f4b2229e6ae614d86d74917f6d5b41890e62a26"
        malpedia_version = "20220516"
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
        $sequence_0 = { 83c002 8bf8 c745fc2a000000 6683383f 7506 83c002 83c602 }
            // n = 7, score = 100
            //   83c002               | add                 eax, 2
            //   8bf8                 | mov                 edi, eax
            //   c745fc2a000000       | mov                 dword ptr [ebp - 4], 0x2a
            //   6683383f             | cmp                 word ptr [eax], 0x3f
            //   7506                 | jne                 8
            //   83c002               | add                 eax, 2
            //   83c602               | add                 esi, 2

        $sequence_1 = { 68???????? 8d95a0f9ffff e8???????? 8d85a0f9ffff 83c424 8d5001 8a08 }
            // n = 7, score = 100
            //   68????????           |                     
            //   8d95a0f9ffff         | lea                 edx, [ebp - 0x660]
            //   e8????????           |                     
            //   8d85a0f9ffff         | lea                 eax, [ebp - 0x660]
            //   83c424               | add                 esp, 0x24
            //   8d5001               | lea                 edx, [eax + 1]
            //   8a08                 | mov                 cl, byte ptr [eax]

        $sequence_2 = { d1f8 0185f8eeffff 8bbdf8eeffff e9???????? 6689847dfceeffff 47 89bdf8eeffff }
            // n = 7, score = 100
            //   d1f8                 | sar                 eax, 1
            //   0185f8eeffff         | add                 dword ptr [ebp - 0x1108], eax
            //   8bbdf8eeffff         | mov                 edi, dword ptr [ebp - 0x1108]
            //   e9????????           |                     
            //   6689847dfceeffff     | mov                 word ptr [ebp + edi*2 - 0x1104], ax
            //   47                   | inc                 edi
            //   89bdf8eeffff         | mov                 dword ptr [ebp - 0x1108], edi

        $sequence_3 = { 6a00 2bc2 50 8d8d94f3ffff 51 56 ff15???????? }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   2bc2                 | sub                 eax, edx
            //   50                   | push                eax
            //   8d8d94f3ffff         | lea                 ecx, [ebp - 0xc6c]
            //   51                   | push                ecx
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_4 = { 83f825 7416 8d8dfcfeffff 43 668901 }
            // n = 5, score = 100
            //   83f825               | cmp                 eax, 0x25
            //   7416                 | je                  0x18
            //   8d8dfcfeffff         | lea                 ecx, [ebp - 0x104]
            //   43                   | inc                 ebx
            //   668901               | mov                 word ptr [ecx], ax

        $sequence_5 = { 56 ffd7 85c0 754b 85f6 7447 53 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax
            //   754b                 | jne                 0x4d
            //   85f6                 | test                esi, esi
            //   7447                 | je                  0x49
            //   53                   | push                ebx

        $sequence_6 = { 84c9 75f9 6a00 2bc2 50 8d45c0 }
            // n = 6, score = 100
            //   84c9                 | test                cl, cl
            //   75f9                 | jne                 0xfffffffb
            //   6a00                 | push                0
            //   2bc2                 | sub                 eax, edx
            //   50                   | push                eax
            //   8d45c0               | lea                 eax, [ebp - 0x40]

        $sequence_7 = { 83c410 85f6 75bb 5b 5f 5e 8be5 }
            // n = 7, score = 100
            //   83c410               | add                 esp, 0x10
            //   85f6                 | test                esi, esi
            //   75bb                 | jne                 0xffffffbd
            //   5b                   | pop                 ebx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8be5                 | mov                 esp, ebp

        $sequence_8 = { 8bd0 52 8d45a0 50 68???????? 68???????? 8d95a0f9ffff }
            // n = 7, score = 100
            //   8bd0                 | mov                 edx, eax
            //   52                   | push                edx
            //   8d45a0               | lea                 eax, [ebp - 0x60]
            //   50                   | push                eax
            //   68????????           |                     
            //   68????????           |                     
            //   8d95a0f9ffff         | lea                 edx, [ebp - 0x660]

        $sequence_9 = { 7507 668378fe2a 7432 837df800 752c }
            // n = 5, score = 100
            //   7507                 | jne                 9
            //   668378fe2a           | cmp                 word ptr [eax - 2], 0x2a
            //   7432                 | je                  0x34
            //   837df800             | cmp                 dword ptr [ebp - 8], 0
            //   752c                 | jne                 0x2e

    condition:
        7 of them and filesize < 191488
}