rule win_cuba_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.cuba."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cuba"
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
        $sequence_0 = { 038d78ffffff 33c6 2385dcfeffff 33c7 03c1 03d0 8b85f0feffff }
            // n = 7, score = 100
            //   038d78ffffff         | add                 ecx, dword ptr [ebp - 0x88]
            //   33c6                 | xor                 eax, esi
            //   2385dcfeffff         | and                 eax, dword ptr [ebp - 0x124]
            //   33c7                 | xor                 eax, edi
            //   03c1                 | add                 eax, ecx
            //   03d0                 | add                 edx, eax
            //   8b85f0feffff         | mov                 eax, dword ptr [ebp - 0x110]

        $sequence_1 = { 50 895df8 e8???????? 8bf0 83c40c 85f6 75af }
            // n = 7, score = 100
            //   50                   | push                eax
            //   895df8               | mov                 dword ptr [ebp - 8], ebx
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c40c               | add                 esp, 0xc
            //   85f6                 | test                esi, esi
            //   75af                 | jne                 0xffffffb1

        $sequence_2 = { 894804 8b85c8f7ffff 8908 8b85dcf7ffff c645fc00 8b95e0f7ffff 8d3446 }
            // n = 7, score = 100
            //   894804               | mov                 dword ptr [eax + 4], ecx
            //   8b85c8f7ffff         | mov                 eax, dword ptr [ebp - 0x838]
            //   8908                 | mov                 dword ptr [eax], ecx
            //   8b85dcf7ffff         | mov                 eax, dword ptr [ebp - 0x824]
            //   c645fc00             | mov                 byte ptr [ebp - 4], 0
            //   8b95e0f7ffff         | mov                 edx, dword ptr [ebp - 0x820]
            //   8d3446               | lea                 esi, [esi + eax*2]

        $sequence_3 = { 68de010000 68???????? 68???????? e8???????? 68df010000 68???????? 68???????? }
            // n = 7, score = 100
            //   68de010000           | push                0x1de
            //   68????????           |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   68df010000           | push                0x1df
            //   68????????           |                     
            //   68????????           |                     

        $sequence_4 = { 8d45b0 50 e8???????? 8bf0 83c40c 85f6 0f852f010000 }
            // n = 7, score = 100
            //   8d45b0               | lea                 eax, [ebp - 0x50]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c40c               | add                 esp, 0xc
            //   85f6                 | test                esi, esi
            //   0f852f010000         | jne                 0x135

        $sequence_5 = { 89410c 85c0 7507 b8feffffff 5d c3 c70100000000 }
            // n = 7, score = 100
            //   89410c               | mov                 dword ptr [ecx + 0xc], eax
            //   85c0                 | test                eax, eax
            //   7507                 | jne                 9
            //   b8feffffff           | mov                 eax, 0xfffffffe
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   c70100000000         | mov                 dword ptr [ecx], 0

        $sequence_6 = { 895dfc 50 57 8b7df4 8945ec 8d041f 50 }
            // n = 7, score = 100
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   50                   | push                eax
            //   57                   | push                edi
            //   8b7df4               | mov                 edi, dword ptr [ebp - 0xc]
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8d041f               | lea                 eax, [edi + ebx]
            //   50                   | push                eax

        $sequence_7 = { c3 8d87c0440000 6a10 50 e8???????? 83c408 33c0 }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   8d87c0440000         | lea                 eax, [edi + 0x44c0]
            //   6a10                 | push                0x10
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   33c0                 | xor                 eax, eax

        $sequence_8 = { 3901 8919 1bc0 83e006 5b 8be5 5d }
            // n = 7, score = 100
            //   3901                 | cmp                 dword ptr [ecx], eax
            //   8919                 | mov                 dword ptr [ecx], ebx
            //   1bc0                 | sbb                 eax, eax
            //   83e006               | and                 eax, 6
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp

        $sequence_9 = { 85d2 7e36 baecffffff 8d4e14 2bd6 800101 }
            // n = 6, score = 100
            //   85d2                 | test                edx, edx
            //   7e36                 | jle                 0x38
            //   baecffffff           | mov                 edx, 0xffffffec
            //   8d4e14               | lea                 ecx, [esi + 0x14]
            //   2bd6                 | sub                 edx, esi
            //   800101               | add                 byte ptr [ecx], 1

    condition:
        7 of them and filesize < 1094656
}