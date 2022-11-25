rule win_jaff_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.jaff."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.jaff"
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
        $sequence_0 = { 394308 0f869a000000 8b0e 668b0c41 8b13 66890c42 40 }
            // n = 7, score = 600
            //   394308               | cmp                 dword ptr [ebx + 8], eax
            //   0f869a000000         | jbe                 0xa0
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   668b0c41             | mov                 cx, word ptr [ecx + eax*2]
            //   8b13                 | mov                 edx, dword ptr [ebx]
            //   66890c42             | mov                 word ptr [edx + eax*2], cx
            //   40                   | inc                 eax

        $sequence_1 = { 83cbff 8b45dc 66891448 41 3b4df8 76a8 8b4d08 }
            // n = 7, score = 600
            //   83cbff               | or                  ebx, 0xffffffff
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   66891448             | mov                 word ptr [eax + ecx*2], dx
            //   41                   | inc                 ecx
            //   3b4df8               | cmp                 ecx, dword ptr [ebp - 8]
            //   76a8                 | jbe                 0xffffffaa
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]

        $sequence_2 = { 8d9568ffffff 52 56 e8???????? 6a14 6a08 8bf8 }
            // n = 7, score = 600
            //   8d9568ffffff         | lea                 edx, [ebp - 0x98]
            //   52                   | push                edx
            //   56                   | push                esi
            //   e8????????           |                     
            //   6a14                 | push                0x14
            //   6a08                 | push                8
            //   8bf8                 | mov                 edi, eax

        $sequence_3 = { 50 ffd3 8945ec b800010000 8d5ddc 8d4dec e8???????? }
            // n = 7, score = 600
            //   50                   | push                eax
            //   ffd3                 | call                ebx
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   b800010000           | mov                 eax, 0x100
            //   8d5ddc               | lea                 ebx, [ebp - 0x24]
            //   8d4dec               | lea                 ecx, [ebp - 0x14]
            //   e8????????           |                     

        $sequence_4 = { 8be5 5d c20800 8b55fc 57 52 6a40 }
            // n = 7, score = 600
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20800               | ret                 8
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   57                   | push                edi
            //   52                   | push                edx
            //   6a40                 | push                0x40

        $sequence_5 = { 6a2d 53 50 e8???????? 83c40c }
            // n = 5, score = 600
            //   6a2d                 | push                0x2d
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_6 = { 8bec 81ec6c040000 53 8b1d???????? 56 57 }
            // n = 6, score = 600
            //   8bec                 | mov                 ebp, esp
            //   81ec6c040000         | sub                 esp, 0x46c
            //   53                   | push                ebx
            //   8b1d????????         |                     
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_7 = { 8d7d90 894dc8 e8???????? 8b4590 50 6a00 }
            // n = 6, score = 600
            //   8d7d90               | lea                 edi, [ebp - 0x70]
            //   894dc8               | mov                 dword ptr [ebp - 0x38], ecx
            //   e8????????           |                     
            //   8b4590               | mov                 eax, dword ptr [ebp - 0x70]
            //   50                   | push                eax
            //   6a00                 | push                0

        $sequence_8 = { 8b3e 8d45fc 50 6a01 57 ff15???????? 85c0 }
            // n = 7, score = 600
            //   8b3e                 | mov                 edi, dword ptr [esi]
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   6a01                 | push                1
            //   57                   | push                edi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_9 = { 66891441 40 3b4608 72ed 8b45dc 50 }
            // n = 6, score = 600
            //   66891441             | mov                 word ptr [ecx + eax*2], dx
            //   40                   | inc                 eax
            //   3b4608               | cmp                 eax, dword ptr [esi + 8]
            //   72ed                 | jb                  0xffffffef
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 106496
}