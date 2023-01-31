rule win_salgorea_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.salgorea."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.salgorea"
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
        $sequence_0 = { 51 66b9bc00 66f7e1 53 c1fb02 d50a 8bc3 }
            // n = 7, score = 300
            //   51                   | push                ecx
            //   66b9bc00             | mov                 cx, 0xbc
            //   66f7e1               | mul                 cx
            //   53                   | push                ebx
            //   c1fb02               | sar                 ebx, 2
            //   d50a                 | aad                 
            //   8bc3                 | mov                 eax, ebx

        $sequence_1 = { 27 664a 43 37 }
            // n = 4, score = 300
            //   27                   | daa                 
            //   664a                 | dec                 dx
            //   43                   | inc                 ebx
            //   37                   | aaa                 

        $sequence_2 = { 51 66b9b469 66f7f1 f7da 66b89e00 66b97900 66f7e1 }
            // n = 7, score = 300
            //   51                   | push                ecx
            //   66b9b469             | mov                 cx, 0x69b4
            //   66f7f1               | div                 cx
            //   f7da                 | neg                 edx
            //   66b89e00             | mov                 ax, 0x9e
            //   66b97900             | mov                 cx, 0x79
            //   66f7e1               | mul                 cx

        $sequence_3 = { 66c1e804 8b44240c 0fbafa00 0fbcd2 8b542418 52 9d }
            // n = 7, score = 300
            //   66c1e804             | shr                 ax, 4
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   0fbafa00             | btc                 edx, 0
            //   0fbcd2               | bsf                 edx, edx
            //   8b542418             | mov                 edx, dword ptr [esp + 0x18]
            //   52                   | push                edx
            //   9d                   | popfd               

        $sequence_4 = { 51 66c1e105 9e f7d1 53 }
            // n = 5, score = 300
            //   51                   | push                ecx
            //   66c1e105             | shl                 cx, 5
            //   9e                   | sahf                
            //   f7d1                 | not                 ecx
            //   53                   | push                ebx

        $sequence_5 = { 66c1e804 f8 660fbae803 f8 0fcb 33d8 }
            // n = 6, score = 300
            //   66c1e804             | shr                 ax, 4
            //   f8                   | clc                 
            //   660fbae803           | bts                 ax, 3
            //   f8                   | clc                 
            //   0fcb                 | bswap               ebx
            //   33d8                 | xor                 ebx, eax

        $sequence_6 = { 51 6698 f7db 33d2 b889510000 b98c0b0000 f7f1 }
            // n = 7, score = 300
            //   51                   | push                ecx
            //   6698                 | cbw                 
            //   f7db                 | neg                 ebx
            //   33d2                 | xor                 edx, edx
            //   b889510000           | mov                 eax, 0x5189
            //   b98c0b0000           | mov                 ecx, 0xb8c
            //   f7f1                 | div                 ecx

        $sequence_7 = { 66c1e306 80eb38 80e6ee f8 f6d1 52 40 }
            // n = 7, score = 300
            //   66c1e306             | shl                 bx, 6
            //   80eb38               | sub                 bl, 0x38
            //   80e6ee               | and                 dh, 0xee
            //   f8                   | clc                 
            //   f6d1                 | not                 cl
            //   52                   | push                edx
            //   40                   | inc                 eax

        $sequence_8 = { a1???????? 8945cc 8d45cc 3930 }
            // n = 4, score = 200
            //   a1????????           |                     
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax
            //   8d45cc               | lea                 eax, [ebp - 0x34]
            //   3930                 | cmp                 dword ptr [eax], esi

        $sequence_9 = { 8d85ecfeffff 6a00 50 e8???????? 83c40c 8d45fc }
            // n = 6, score = 100
            //   8d85ecfeffff         | lea                 eax, [ebp - 0x114]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d45fc               | lea                 eax, [ebp - 4]

        $sequence_10 = { 8d85e4feffff 50 ff7510 e8???????? 85c0 }
            // n = 5, score = 100
            //   8d85e4feffff         | lea                 eax, [ebp - 0x11c]
            //   50                   | push                eax
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_11 = { 8d85e8feffff 50 681c004000 ffb5f8feffff }
            // n = 4, score = 100
            //   8d85e8feffff         | lea                 eax, [ebp - 0x118]
            //   50                   | push                eax
            //   681c004000           | push                0x40001c
            //   ffb5f8feffff         | push                dword ptr [ebp - 0x108]

        $sequence_12 = { 8d85e8feffff 50 e8???????? 8bf0 83c40c }
            // n = 5, score = 100
            //   8d85e8feffff         | lea                 eax, [ebp - 0x118]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c40c               | add                 esp, 0xc

        $sequence_13 = { 8d85f0fdffff 50 8b4708 83c071 }
            // n = 4, score = 100
            //   8d85f0fdffff         | lea                 eax, [ebp - 0x210]
            //   50                   | push                eax
            //   8b4708               | mov                 eax, dword ptr [edi + 8]
            //   83c071               | add                 eax, 0x71

        $sequence_14 = { 8d85ecfeffff 50 ff750c ff15???????? }
            // n = 4, score = 100
            //   8d85ecfeffff         | lea                 eax, [ebp - 0x114]
            //   50                   | push                eax
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff15????????         |                     

        $sequence_15 = { 8d85e8feffff 6800010000 50 e8???????? }
            // n = 4, score = 100
            //   8d85e8feffff         | lea                 eax, [ebp - 0x118]
            //   6800010000           | push                0x100
            //   50                   | push                eax
            //   e8????????           |                     

    condition:
        7 of them and filesize < 2007040
}