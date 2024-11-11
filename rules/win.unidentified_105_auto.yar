rule win_unidentified_105_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.unidentified_105."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_105"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
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
        $sequence_0 = { 51 53 56 57 6800002000 }
            // n = 5, score = 200
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   6800002000           | push                0x200000

        $sequence_1 = { 8d542420 e8???????? 85c0 740d 6a64 ff15???????? }
            // n = 6, score = 200
            //   8d542420             | lea                 edx, [esp + 0x20]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   740d                 | je                  0xf
            //   6a64                 | push                0x64
            //   ff15????????         |                     

        $sequence_2 = { 84d2 75f9 2bc1 8bf8 8d4f02 }
            // n = 5, score = 200
            //   84d2                 | test                dl, dl
            //   75f9                 | jne                 0xfffffffb
            //   2bc1                 | sub                 eax, ecx
            //   8bf8                 | mov                 edi, eax
            //   8d4f02               | lea                 ecx, [edi + 2]

        $sequence_3 = { 50 51 68???????? 53 e8???????? 8b95ecfeffff }
            // n = 6, score = 200
            //   50                   | push                eax
            //   51                   | push                ecx
            //   68????????           |                     
            //   53                   | push                ebx
            //   e8????????           |                     
            //   8b95ecfeffff         | mov                 edx, dword ptr [ebp - 0x114]

        $sequence_4 = { 8945fc 83ff04 7e7b 8d57fb c1ea02 42 }
            // n = 6, score = 200
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   83ff04               | cmp                 edi, 4
            //   7e7b                 | jle                 0x7d
            //   8d57fb               | lea                 edx, [edi - 5]
            //   c1ea02               | shr                 edx, 2
            //   42                   | inc                 edx

        $sequence_5 = { e8???????? 6800002000 8bd8 6a00 53 e8???????? }
            // n = 6, score = 200
            //   e8????????           |                     
            //   6800002000           | push                0x200000
            //   8bd8                 | mov                 ebx, eax
            //   6a00                 | push                0
            //   53                   | push                ebx
            //   e8????????           |                     

        $sequence_6 = { 75f9 2b55f0 8d45f8 50 53 52 }
            // n = 6, score = 200
            //   75f9                 | jne                 0xfffffffb
            //   2b55f0               | sub                 edx, dword ptr [ebp - 0x10]
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   52                   | push                edx

        $sequence_7 = { 50 68???????? 52 e8???????? 83c414 6800020000 e8???????? }
            // n = 7, score = 200
            //   50                   | push                eax
            //   68????????           |                     
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   6800020000           | push                0x200
            //   e8????????           |                     

        $sequence_8 = { 8818 3bca 752a 0fbe0c31 83e103 }
            // n = 5, score = 200
            //   8818                 | mov                 byte ptr [eax], bl
            //   3bca                 | cmp                 ecx, edx
            //   752a                 | jne                 0x2c
            //   0fbe0c31             | movsx               ecx, byte ptr [ecx + esi]
            //   83e103               | and                 ecx, 3

        $sequence_9 = { 56 8d95f8efffff 52 8d041f 50 e8???????? 8b85f4efffff }
            // n = 7, score = 200
            //   56                   | push                esi
            //   8d95f8efffff         | lea                 edx, [ebp - 0x1008]
            //   52                   | push                edx
            //   8d041f               | lea                 eax, [edi + ebx]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b85f4efffff         | mov                 eax, dword ptr [ebp - 0x100c]

    condition:
        7 of them and filesize < 253952
}