rule win_unidentified_039_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.unidentified_039."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_039"
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
        $sequence_0 = { 8b4538 8b4d28 2d674d0000 0bc1 894538 8b45e4 c645fc01 }
            // n = 7, score = 100
            //   8b4538               | mov                 eax, dword ptr [ebp + 0x38]
            //   8b4d28               | mov                 ecx, dword ptr [ebp + 0x28]
            //   2d674d0000           | sub                 eax, 0x4d67
            //   0bc1                 | or                  eax, ecx
            //   894538               | mov                 dword ptr [ebp + 0x38], eax
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1

        $sequence_1 = { 8b4594 8b4d98 3bc8 7c10 53 ff7590 }
            // n = 6, score = 100
            //   8b4594               | mov                 eax, dword ptr [ebp - 0x6c]
            //   8b4d98               | mov                 ecx, dword ptr [ebp - 0x68]
            //   3bc8                 | cmp                 ecx, eax
            //   7c10                 | jl                  0x12
            //   53                   | push                ebx
            //   ff7590               | push                dword ptr [ebp - 0x70]

        $sequence_2 = { 8945f8 6a73 33ff 47 57 6a65 }
            // n = 6, score = 100
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   6a73                 | push                0x73
            //   33ff                 | xor                 edi, edi
            //   47                   | inc                 edi
            //   57                   | push                edi
            //   6a65                 | push                0x65

        $sequence_3 = { 8b4598 33c8 8b4588 69c08b340000 0bc8 894d9c }
            // n = 6, score = 100
            //   8b4598               | mov                 eax, dword ptr [ebp - 0x68]
            //   33c8                 | xor                 ecx, eax
            //   8b4588               | mov                 eax, dword ptr [ebp - 0x78]
            //   69c08b340000         | imul                eax, eax, 0x348b
            //   0bc8                 | or                  ecx, eax
            //   894d9c               | mov                 dword ptr [ebp - 0x64], ecx

        $sequence_4 = { 53 ff75e8 ff75ec ff75f0 ff15???????? 3bfb 0f840e010000 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   ff15????????         |                     
            //   3bfb                 | cmp                 edi, ebx
            //   0f840e010000         | je                  0x114

        $sequence_5 = { 8b45ec 8b4df0 3bc8 7d0c ff75f0 ff75e0 ff15???????? }
            // n = 7, score = 100
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   3bc8                 | cmp                 ecx, eax
            //   7d0c                 | jge                 0xe
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   ff75e0               | push                dword ptr [ebp - 0x20]
            //   ff15????????         |                     

        $sequence_6 = { 89459c 8b4598 8b4d94 3bc8 7d0c ff7594 ff15???????? }
            // n = 7, score = 100
            //   89459c               | mov                 dword ptr [ebp - 0x64], eax
            //   8b4598               | mov                 eax, dword ptr [ebp - 0x68]
            //   8b4d94               | mov                 ecx, dword ptr [ebp - 0x6c]
            //   3bc8                 | cmp                 ecx, eax
            //   7d0c                 | jge                 0xe
            //   ff7594               | push                dword ptr [ebp - 0x6c]
            //   ff15????????         |                     

        $sequence_7 = { 8b55ec 2bd1 81e244620000 0bc2 8945f4 }
            // n = 5, score = 100
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   2bd1                 | sub                 edx, ecx
            //   81e244620000         | and                 edx, 0x6244
            //   0bc2                 | or                  eax, edx
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax

        $sequence_8 = { 8b4d98 23c1 8b4d9c 33c1 }
            // n = 4, score = 100
            //   8b4d98               | mov                 ecx, dword ptr [ebp - 0x68]
            //   23c1                 | and                 eax, ecx
            //   8b4d9c               | mov                 ecx, dword ptr [ebp - 0x64]
            //   33c1                 | xor                 eax, ecx

        $sequence_9 = { 53 53 56 ff15???????? c745d44f6f0000 c745d842400000 c745d4f0460000 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   56                   | push                esi
            //   ff15????????         |                     
            //   c745d44f6f0000       | mov                 dword ptr [ebp - 0x2c], 0x6f4f
            //   c745d842400000       | mov                 dword ptr [ebp - 0x28], 0x4042
            //   c745d4f0460000       | mov                 dword ptr [ebp - 0x2c], 0x46f0

    condition:
        7 of them and filesize < 262144
}