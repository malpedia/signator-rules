rule win_ripper_atm_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.ripper_atm."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ripper_atm"
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
        $sequence_0 = { 8d45d8 50 6a01 53 ff15???????? 8b35???????? 85c0 }
            // n = 7, score = 100
            //   8d45d8               | lea                 eax, [ebp - 0x28]
            //   50                   | push                eax
            //   6a01                 | push                1
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_1 = { 8b0e e8???????? 8b10 ff7508 8bc8 ff5210 8b0e }
            // n = 7, score = 100
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   e8????????           |                     
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8bc8                 | mov                 ecx, eax
            //   ff5210               | call                dword ptr [edx + 0x10]
            //   8b0e                 | mov                 ecx, dword ptr [esi]

        $sequence_2 = { 89440af4 c3 51 c701???????? e8???????? 59 }
            // n = 6, score = 100
            //   89440af4             | mov                 dword ptr [edx + ecx - 0xc], eax
            //   c3                   | ret                 
            //   51                   | push                ecx
            //   c701????????         |                     
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_3 = { 33c0 8bca 83e107 40 d3e0 8b4dfc c1ea03 }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   8bca                 | mov                 ecx, edx
            //   83e107               | and                 ecx, 7
            //   40                   | inc                 eax
            //   d3e0                 | shl                 eax, cl
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   c1ea03               | shr                 edx, 3

        $sequence_4 = { 8d85bcf7ffff 50 e8???????? 83780800 7447 8d85bcf7ffff }
            // n = 6, score = 100
            //   8d85bcf7ffff         | lea                 eax, [ebp - 0x844]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83780800             | cmp                 dword ptr [eax + 8], 0
            //   7447                 | je                  0x49
            //   8d85bcf7ffff         | lea                 eax, [ebp - 0x844]

        $sequence_5 = { 83c008 894508 3b450c 75e4 }
            // n = 4, score = 100
            //   83c008               | add                 eax, 8
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   3b450c               | cmp                 eax, dword ptr [ebp + 0xc]
            //   75e4                 | jne                 0xffffffe6

        $sequence_6 = { e8???????? 8b00 8b0b 394810 7313 8b45ec }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8b0b                 | mov                 ecx, dword ptr [ebx]
            //   394810               | cmp                 dword ptr [eax + 0x10], ecx
            //   7313                 | jae                 0x15
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]

        $sequence_7 = { 8b46a0 8d4ea4 8b4004 c74430a0c0224300 8b46a0 8b5004 8d42a0 }
            // n = 7, score = 100
            //   8b46a0               | mov                 eax, dword ptr [esi - 0x60]
            //   8d4ea4               | lea                 ecx, [esi - 0x5c]
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   c74430a0c0224300     | mov                 dword ptr [eax + esi - 0x60], 0x4322c0
            //   8b46a0               | mov                 eax, dword ptr [esi - 0x60]
            //   8b5004               | mov                 edx, dword ptr [eax + 4]
            //   8d42a0               | lea                 eax, [edx - 0x60]

        $sequence_8 = { 58 0f44f0 6a18 e8???????? 59 85c0 7419 }
            // n = 7, score = 100
            //   58                   | pop                 eax
            //   0f44f0               | cmove               esi, eax
            //   6a18                 | push                0x18
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   7419                 | je                  0x1b

        $sequence_9 = { 48 3bc3 0f8299000000 2b0f 56 03cb 51 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   3bc3                 | cmp                 eax, ebx
            //   0f8299000000         | jb                  0x9f
            //   2b0f                 | sub                 ecx, dword ptr [edi]
            //   56                   | push                esi
            //   03cb                 | add                 ecx, ebx
            //   51                   | push                ecx

    condition:
        7 of them and filesize < 724992
}