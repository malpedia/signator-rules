rule win_poortry_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.poortry."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.poortry"
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
        $sequence_0 = { f5 f9 49f7c4467a0073 4152 440fbfd2 6641d3e2 4180d2ac }
            // n = 7, score = 100
            //   f5                   | cmc                 
            //   f9                   | stc                 
            //   49f7c4467a0073       | xor                 edx, 0x775d13d7
            //   4152                 | ror                 edx, 2
            //   440fbfd2             | inc                 esp
            //   6641d3e2             | test                dl, ch
            //   4180d2ac             | add                 edx, 0x60794b60

        $sequence_1 = { 5f f8 66a9421f f9 4d63d2 664181f95617 }
            // n = 6, score = 100
            //   5f                   | mov                 dword ptr [eax + 8], edx
            //   f8                   | inc                 ax
            //   66a9421f             | movzx               eax, ch
            //   f9                   | pushfd              
            //   4d63d2               | dec                 eax
            //   664181f95617         | adc                 eax, 0x1b816c5

        $sequence_2 = { 4086f6 40fece 5e f5 41f6c3a9 443ac1 4863c0 }
            // n = 7, score = 100
            //   4086f6               | shr                 dx, cl
            //   40fece               | sar                 dl, 0xee
            //   5e                   | neg                 bl
            //   f5                   | bswap               dx
            //   41f6c3a9             | clc                 
            //   443ac1               | rol                 eax, 1
            //   4863c0               | cmc                 

        $sequence_3 = { 81e96a254506 f9 c1c103 443bcd f9 f5 4152 }
            // n = 7, score = 100
            //   81e96a254506         | xor                 dword ptr [esp], eax
            //   f9                   | dec                 ecx
            //   c1c103               | movzx               edi, di
            //   443bcd               | stc                 
            //   f9                   | push                edi
            //   f5                   | stc                 
            //   4152                 | dec                 ecx

        $sequence_4 = { 488b16 2aca f8 8a4e08 f5 6681fa0307 e9???????? }
            // n = 7, score = 100
            //   488b16               | setle               al
            //   2aca                 | inc                 ecx
            //   f8                   | not                 dl
            //   8a4e08               | xor                 dword ptr [esp], edx
            //   f5                   | inc                 ebp
            //   6681fa0307           | cmovp               edx, ebp
            //   e9????????           |                     

        $sequence_5 = { 4180fe99 c1e203 1c55 488bc5 488d0410 493bc2 664485d9 }
            // n = 7, score = 100
            //   4180fe99             | dec                 ebp
            //   c1e203               | cmp                 ecx, ebp
            //   1c55                 | je                  0x566
            //   488bc5               | inc                 ecx
            //   488d0410             | movzx               eax, byte ptr [ecx]
            //   493bc2               | inc                 esp
            //   664485d9             | btr                 ecx, ecx

        $sequence_6 = { 41895008 4189400c 410f98c2 440fbfd1 66440fbed4 9c }
            // n = 6, score = 100
            //   41895008             | pushfd              
            //   4189400c             | bswap               edx
            //   410f98c2             | inc                 ecx
            //   440fbfd1             | test                cl, 0x85
            //   66440fbed4           | push                esi
            //   9c                   | xor                 dword ptr [esp], edx

        $sequence_7 = { 311424 5d 6681fc4d15 4585cb 4863d2 f9 f8 }
            // n = 7, score = 100
            //   311424               | not                 dh
            //   5d                   | inc                 ecx
            //   6681fc4d15           | and                 dl, al
            //   4585cb               | inc                 eax
            //   4863d2               | xor                 dh, bl
            //   f9                   | inc                 sp
            //   f8                   | mov                 dword ptr [esp + ebx], ebx

        $sequence_8 = { 4981d342615869 41c0c30b 415b 3cc3 f9 4863c0 }
            // n = 6, score = 100
            //   4981d342615869       | xor                 dword ptr [esp], edx
            //   41c0c30b             | inc                 sp
            //   415b                 | bt                  esi, ebp
            //   3cc3                 | inc                 ecx
            //   f9                   | dec                 edx
            //   4863c0               | push                esi

        $sequence_9 = { 4150 c3 488be5 4185f6 491bf1 4080e6e4 5f }
            // n = 7, score = 100
            //   4150                 | inc                 al
            //   c3                   | inc                 cx
            //   488be5               | btr                 edx, 0xb7
            //   4185f6               | inc                 bp
            //   491bf1               | btr                 edx, edi
            //   4080e6e4             | rol                 al, 1
            //   5f                   | inc                 cx

    condition:
        7 of them and filesize < 8078336
}