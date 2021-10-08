rule win_unidentified_031_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.unidentified_031."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_031"
        malpedia_rule_date = "20211007"
        malpedia_hash = "e5b790e0f888f252d49063a1251ca60ec2832535"
        malpedia_version = "20211008"
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
        $sequence_0 = { 6a00 ff75f0 6a00 53 ff7668 e8???????? 688d130000 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   6a00                 | push                0
            //   53                   | push                ebx
            //   ff7668               | push                dword ptr [esi + 0x68]
            //   e8????????           |                     
            //   688d130000           | push                0x138d

        $sequence_1 = { ff7508 e8???????? 85c0 7413 8b4804 81f900000100 740c }
            // n = 7, score = 100
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7413                 | je                  0x15
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   81f900000100         | cmp                 ecx, 0x10000
            //   740c                 | je                  0xe

        $sequence_2 = { 8d4dcc 8d95f8feffff 51 52 899d00ffffff c785f8feffff02800000 ff15???????? }
            // n = 7, score = 100
            //   8d4dcc               | lea                 ecx, dword ptr [ebp - 0x34]
            //   8d95f8feffff         | lea                 edx, dword ptr [ebp - 0x108]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   899d00ffffff         | mov                 dword ptr [ebp - 0x100], ebx
            //   c785f8feffff02800000     | mov    dword ptr [ebp - 0x108], 0x8002
            //   ff15????????         |                     

        $sequence_3 = { 8d8548ffffff 8d8d78ffffff 50 8d5588 51 8d8558ffffff 52 }
            // n = 7, score = 100
            //   8d8548ffffff         | lea                 eax, dword ptr [ebp - 0xb8]
            //   8d8d78ffffff         | lea                 ecx, dword ptr [ebp - 0x88]
            //   50                   | push                eax
            //   8d5588               | lea                 edx, dword ptr [ebp - 0x78]
            //   51                   | push                ecx
            //   8d8558ffffff         | lea                 eax, dword ptr [ebp - 0xa8]
            //   52                   | push                edx

        $sequence_4 = { 83e801 0f804f020000 50 e8???????? 8bd0 8d4dc8 ffd6 }
            // n = 7, score = 100
            //   83e801               | sub                 eax, 1
            //   0f804f020000         | jo                  0x255
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bd0                 | mov                 edx, eax
            //   8d4dc8               | lea                 ecx, dword ptr [ebp - 0x38]
            //   ffd6                 | call                esi

        $sequence_5 = { 52 50 ff15???????? 8d9548ffffff 8d4dac ffd6 8d8d58ffffff }
            // n = 7, score = 100
            //   52                   | push                edx
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d9548ffffff         | lea                 edx, dword ptr [ebp - 0xb8]
            //   8d4dac               | lea                 ecx, dword ptr [ebp - 0x54]
            //   ffd6                 | call                esi
            //   8d8d58ffffff         | lea                 ecx, dword ptr [ebp - 0xa8]

        $sequence_6 = { 8d8dc8fdffff 50 8d95e8feffff 51 52 ffd6 50 }
            // n = 7, score = 100
            //   8d8dc8fdffff         | lea                 ecx, dword ptr [ebp - 0x238]
            //   50                   | push                eax
            //   8d95e8feffff         | lea                 edx, dword ptr [ebp - 0x118]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   ffd6                 | call                esi
            //   50                   | push                eax

        $sequence_7 = { 7403 50 ffd7 8b06 8b4010 85c0 7403 }
            // n = 7, score = 100
            //   7403                 | je                  5
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8b4010               | mov                 eax, dword ptr [eax + 0x10]
            //   85c0                 | test                eax, eax
            //   7403                 | je                  5

        $sequence_8 = { 68281b0001 8d45d4 50 ffd6 f6830502000040 ff7570 ff7574 }
            // n = 7, score = 100
            //   68281b0001           | push                0x1001b28
            //   8d45d4               | lea                 eax, dword ptr [ebp - 0x2c]
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   f6830502000040       | test                byte ptr [ebx + 0x205], 0x40
            //   ff7570               | push                dword ptr [ebp + 0x70]
            //   ff7574               | push                dword ptr [ebp + 0x74]

        $sequence_9 = { 895ddc 53 bf8d130000 57 e8???????? 50 6a07 }
            // n = 7, score = 100
            //   895ddc               | mov                 dword ptr [ebp - 0x24], ebx
            //   53                   | push                ebx
            //   bf8d130000           | mov                 edi, 0x138d
            //   57                   | push                edi
            //   e8????????           |                     
            //   50                   | push                eax
            //   6a07                 | push                7

    condition:
        7 of them and filesize < 1998848
}