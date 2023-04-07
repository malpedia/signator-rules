rule win_recordbreaker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.recordbreaker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.recordbreaker"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
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
        $sequence_0 = { ff15???????? 57 ff750c 8bf0 }
            // n = 4, score = 600
            //   ff15????????         |                     
            //   57                   | push                edi
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   8bf0                 | mov                 esi, eax

        $sequence_1 = { 53 56 8bf2 8bc7 66833800 7408 83c002 }
            // n = 7, score = 600
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8bf2                 | mov                 esi, edx
            //   8bc7                 | mov                 eax, edi
            //   66833800             | cmp                 word ptr [eax], 0
            //   7408                 | je                  0xa
            //   83c002               | add                 eax, 2

        $sequence_2 = { 8b45fc 33d2 f7f1 8bc2 5e c9 c3 }
            // n = 7, score = 600
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   33d2                 | xor                 edx, edx
            //   f7f1                 | div                 ecx
            //   8bc2                 | mov                 eax, edx
            //   5e                   | pop                 esi
            //   c9                   | leave               
            //   c3                   | ret                 

        $sequence_3 = { 3bc7 7e29 8b0b 8bd6 e8???????? 8b15???????? 8bc8 }
            // n = 7, score = 600
            //   3bc7                 | cmp                 eax, edi
            //   7e29                 | jle                 0x2b
            //   8b0b                 | mov                 ecx, dword ptr [ebx]
            //   8bd6                 | mov                 edx, esi
            //   e8????????           |                     
            //   8b15????????         |                     
            //   8bc8                 | mov                 ecx, eax

        $sequence_4 = { ff15???????? 6a02 ff75fc ff15???????? 6a03 }
            // n = 5, score = 600
            //   ff15????????         |                     
            //   6a02                 | push                2
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff15????????         |                     
            //   6a03                 | push                3

        $sequence_5 = { 51 8b4dfc 8975d0 e8???????? }
            // n = 4, score = 600
            //   51                   | push                ecx
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8975d0               | mov                 dword ptr [ebp - 0x30], esi
            //   e8????????           |                     

        $sequence_6 = { 8bd7 8bc8 e8???????? 8b15???????? 8bc8 e8???????? }
            // n = 6, score = 600
            //   8bd7                 | mov                 edx, edi
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   8b15????????         |                     
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     

        $sequence_7 = { 8b5510 8d8d98fdffff e8???????? 85c0 }
            // n = 4, score = 600
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   8d8d98fdffff         | lea                 ecx, [ebp - 0x268]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_8 = { e8???????? eb05 b857000780 5f 5d }
            // n = 5, score = 600
            //   e8????????           |                     
            //   eb05                 | jmp                 7
            //   b857000780           | mov                 eax, 0x80070057
            //   5f                   | pop                 edi
            //   5d                   | pop                 ebp

        $sequence_9 = { 53 ff15???????? 6a00 ff15???????? 5f 5e 5b }
            // n = 7, score = 600
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

    condition:
        7 of them and filesize < 232312
}