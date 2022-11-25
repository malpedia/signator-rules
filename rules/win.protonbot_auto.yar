rule win_protonbot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.protonbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.protonbot"
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
        $sequence_0 = { 0f4395d4feffff 8bca c785b8feffff0f000000 c685a4feffff00 8d7101 8a01 41 }
            // n = 7, score = 400
            //   0f4395d4feffff       | cmovae              edx, dword ptr [ebp - 0x12c]
            //   8bca                 | mov                 ecx, edx
            //   c785b8feffff0f000000     | mov    dword ptr [ebp - 0x148], 0xf
            //   c685a4feffff00       | mov                 byte ptr [ebp - 0x15c], 0
            //   8d7101               | lea                 esi, [ecx + 1]
            //   8a01                 | mov                 al, byte ptr [ecx]
            //   41                   | inc                 ecx

        $sequence_1 = { 83c404 8bf8 8d8560feffff 50 6801010000 8937 }
            // n = 6, score = 400
            //   83c404               | add                 esp, 4
            //   8bf8                 | mov                 edi, eax
            //   8d8560feffff         | lea                 eax, [ebp - 0x1a0]
            //   50                   | push                eax
            //   6801010000           | push                0x101
            //   8937                 | mov                 dword ptr [edi], esi

        $sequence_2 = { 8d8584fbffff 50 e8???????? 83c418 83bd84fbffff00 }
            // n = 5, score = 400
            //   8d8584fbffff         | lea                 eax, [ebp - 0x47c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   83bd84fbffff00       | cmp                 dword ptr [ebp - 0x47c], 0

        $sequence_3 = { 8b00 a3???????? 8d4520 0f434520 50 e8???????? 83c404 }
            // n = 7, score = 400
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   a3????????           |                     
            //   8d4520               | lea                 eax, [ebp + 0x20]
            //   0f434520             | cmovae              eax, dword ptr [ebp + 0x20]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_4 = { c6858cfeffff00 8d7101 8a01 41 }
            // n = 4, score = 400
            //   c6858cfeffff00       | mov                 byte ptr [ebp - 0x174], 0
            //   8d7101               | lea                 esi, [ecx + 1]
            //   8a01                 | mov                 al, byte ptr [ecx]
            //   41                   | inc                 ecx

        $sequence_5 = { 0f438da4feffff 6a07 51 ff15???????? 56 85c0 }
            // n = 6, score = 400
            //   0f438da4feffff       | cmovae              ecx, dword ptr [ebp - 0x15c]
            //   6a07                 | push                7
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   56                   | push                esi
            //   85c0                 | test                eax, eax

        $sequence_6 = { 8d8dbcfeffff e9???????? 8d8dd4feffff e9???????? 8d8da4feffff }
            // n = 5, score = 400
            //   8d8dbcfeffff         | lea                 ecx, [ebp - 0x144]
            //   e9????????           |                     
            //   8d8dd4feffff         | lea                 ecx, [ebp - 0x12c]
            //   e9????????           |                     
            //   8d8da4feffff         | lea                 ecx, [ebp - 0x15c]

        $sequence_7 = { 8d85f0feffff 50 8d85d4feffff 50 e8???????? }
            // n = 5, score = 400
            //   8d85f0feffff         | lea                 eax, [ebp - 0x110]
            //   50                   | push                eax
            //   8d85d4feffff         | lea                 eax, [ebp - 0x12c]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_8 = { 50 e8???????? 83c404 50 ff15???????? 8b1d???????? }
            // n = 6, score = 400
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b1d????????         |                     

        $sequence_9 = { 51 ff15???????? 8bd0 8995c0f7ffff 85d2 }
            // n = 5, score = 400
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8bd0                 | mov                 edx, eax
            //   8995c0f7ffff         | mov                 dword ptr [ebp - 0x840], edx
            //   85d2                 | test                edx, edx

    condition:
        7 of them and filesize < 1073152
}