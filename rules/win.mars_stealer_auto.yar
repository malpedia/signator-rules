rule win_mars_stealer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.mars_stealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mars_stealer"
        malpedia_rule_date = "20221118"
        malpedia_hash = "e0702e2e6d1d00da65c8a29a4ebacd0a4c59e1af"
        malpedia_version = "20221125"
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
        $sequence_0 = { 8b4508 50 e8???????? 83c414 8b4d1c 51 8b5518 }
            // n = 7, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   8b4d1c               | mov                 ecx, dword ptr [ebp + 0x1c]
            //   51                   | push                ecx
            //   8b5518               | mov                 edx, dword ptr [ebp + 0x18]

        $sequence_1 = { 8b95f4f9ffff 52 ff15???????? a1???????? }
            // n = 4, score = 100
            //   8b95f4f9ffff         | mov                 edx, dword ptr [ebp - 0x60c]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   a1????????           |                     

        $sequence_2 = { ff15???????? 83c404 8985d0feffff 8b85d0feffff 8945f4 6a00 8d4dfc }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4
            //   8985d0feffff         | mov                 dword ptr [ebp - 0x130], eax
            //   8b85d0feffff         | mov                 eax, dword ptr [ebp - 0x130]
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   6a00                 | push                0
            //   8d4dfc               | lea                 ecx, [ebp - 4]

        $sequence_3 = { e8???????? 83c404 8bc8 8b85f4fbffff 33d2 f7f1 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8bc8                 | mov                 ecx, eax
            //   8b85f4fbffff         | mov                 eax, dword ptr [ebp - 0x40c]
            //   33d2                 | xor                 edx, edx
            //   f7f1                 | div                 ecx

        $sequence_4 = { 6bc934 034dfc 898d3cfbffff b904000000 bf???????? }
            // n = 5, score = 100
            //   6bc934               | imul                ecx, ecx, 0x34
            //   034dfc               | add                 ecx, dword ptr [ebp - 4]
            //   898d3cfbffff         | mov                 dword ptr [ebp - 0x4c4], ecx
            //   b904000000           | mov                 ecx, 4
            //   bf????????           |                     

        $sequence_5 = { e8???????? 83c40c 8b450c 0fb70cc5ba664100 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   0fb70cc5ba664100     | movzx               ecx, word ptr [eax*8 + 0x4166ba]

        $sequence_6 = { 51 ff15???????? 8d95a8fcffff 52 8d85a0fbffff }
            // n = 5, score = 100
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8d95a8fcffff         | lea                 edx, [ebp - 0x358]
            //   52                   | push                edx
            //   8d85a0fbffff         | lea                 eax, [ebp - 0x460]

        $sequence_7 = { 51 ff15???????? 8b95d4d6ffff 52 8d8578ecffff 50 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8b95d4d6ffff         | mov                 edx, dword ptr [ebp - 0x292c]
            //   52                   | push                edx
            //   8d8578ecffff         | lea                 eax, [ebp - 0x1388]
            //   50                   | push                eax

        $sequence_8 = { e8???????? 8b4508 83e001 740d 8b4dfc 51 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83e001               | and                 eax, 1
            //   740d                 | je                  0xf
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   51                   | push                ecx

        $sequence_9 = { 50 ff15???????? 83c404 8985dcf7ffff 8b85dcf7ffff }
            // n = 5, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4
            //   8985dcf7ffff         | mov                 dword ptr [ebp - 0x824], eax
            //   8b85dcf7ffff         | mov                 eax, dword ptr [ebp - 0x824]

    condition:
        7 of them and filesize < 219136
}