rule win_formbook_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.formbook."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.formbook"
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
        $sequence_0 = { 57 8b7d08 6a00 6a01 56 57 e8???????? }
            // n = 7, score = 1700
            //   57                   | push                edi
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   56                   | push                esi
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_1 = { 52 e8???????? 83c408 85c0 750d 8b36 394618 }
            // n = 7, score = 1700
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   750d                 | jne                 0xf
            //   8b36                 | mov                 esi, dword ptr [esi]
            //   394618               | cmp                 dword ptr [esi + 0x18], eax

        $sequence_2 = { 6a02 57 8906 e8???????? 6a03 57 894604 }
            // n = 7, score = 1700
            //   6a02                 | push                2
            //   57                   | push                edi
            //   8906                 | mov                 dword ptr [esi], eax
            //   e8????????           |                     
            //   6a03                 | push                3
            //   57                   | push                edi
            //   894604               | mov                 dword ptr [esi + 4], eax

        $sequence_3 = { 50 8d8df6f7ffff 51 c745fc00000000 668985f4f7ffff e8???????? 8b7508 }
            // n = 7, score = 1700
            //   50                   | push                eax
            //   8d8df6f7ffff         | lea                 ecx, dword ptr [ebp - 0x80a]
            //   51                   | push                ecx
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   668985f4f7ffff       | mov                 word ptr [ebp - 0x80c], ax
            //   e8????????           |                     
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]

        $sequence_4 = { 56 e8???????? 83c40c 85c0 74e9 8bc6 5e }
            // n = 7, score = 1700
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   74e9                 | je                  0xffffffeb
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi

        $sequence_5 = { 752f 8b5604 6a0a 8d4df4 51 52 e8???????? }
            // n = 7, score = 1700
            //   752f                 | jne                 0x31
            //   8b5604               | mov                 edx, dword ptr [esi + 4]
            //   6a0a                 | push                0xa
            //   8d4df4               | lea                 ecx, dword ptr [ebp - 0xc]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_6 = { 6a00 50 56 e8???????? 8b0f 51 56 }
            // n = 7, score = 1700
            //   6a00                 | push                0
            //   50                   | push                eax
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   51                   | push                ecx
            //   56                   | push                esi

        $sequence_7 = { 004e2a 53 56 e8???????? 83c408 5f 5e }
            // n = 7, score = 1700
            //   004e2a               | add                 byte ptr [esi + 0x2a], cl
            //   53                   | push                ebx
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

    condition:
        7 of them and filesize < 371712
}