rule win_agfspy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.agfspy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.agfspy"
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
        $sequence_0 = { 8d8d14ffffff c645fc04 e8???????? 8d8530fcffff 50 57 e8???????? }
            // n = 7, score = 300
            //   8d8d14ffffff         | lea                 ecx, [ebp - 0xec]
            //   c645fc04             | mov                 byte ptr [ebp - 4], 4
            //   e8????????           |                     
            //   8d8530fcffff         | lea                 eax, [ebp - 0x3d0]
            //   50                   | push                eax
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_1 = { 0f85b2000000 384510 7537 8b4d0c 85c9 7425 8b411c }
            // n = 7, score = 300
            //   0f85b2000000         | jne                 0xb8
            //   384510               | cmp                 byte ptr [ebp + 0x10], al
            //   7537                 | jne                 0x39
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   85c9                 | test                ecx, ecx
            //   7425                 | je                  0x27
            //   8b411c               | mov                 eax, dword ptr [ecx + 0x1c]

        $sequence_2 = { 8b06 83c002 8906 8bce e8???????? 837e4c5d 7573 }
            // n = 7, score = 300
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   83c002               | add                 eax, 2
            //   8906                 | mov                 dword ptr [esi], eax
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   837e4c5d             | cmp                 dword ptr [esi + 0x4c], 0x5d
            //   7573                 | jne                 0x75

        $sequence_3 = { 668945d8 807d1c00 8d4db0 c745fc01000000 8b06 51 8bce }
            // n = 7, score = 300
            //   668945d8             | mov                 word ptr [ebp - 0x28], ax
            //   807d1c00             | cmp                 byte ptr [ebp + 0x1c], 0
            //   8d4db0               | lea                 ecx, [ebp - 0x50]
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   51                   | push                ecx
            //   8bce                 | mov                 ecx, esi

        $sequence_4 = { 8bce 50 e8???????? 83c702 3bfb 75ee 8b7da0 }
            // n = 7, score = 300
            //   8bce                 | mov                 ecx, esi
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c702               | add                 edi, 2
            //   3bfb                 | cmp                 edi, ebx
            //   75ee                 | jne                 0xfffffff0
            //   8b7da0               | mov                 edi, dword ptr [ebp - 0x60]

        $sequence_5 = { c7403800000000 c7403c00000000 8b45e0 8b4df4 64890d00000000 59 5f }
            // n = 7, score = 300
            //   c7403800000000       | mov                 dword ptr [eax + 0x38], 0
            //   c7403c00000000       | mov                 dword ptr [eax + 0x3c], 0
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   59                   | pop                 ecx
            //   5f                   | pop                 edi

        $sequence_6 = { 51 0f8293000000 8b1e 53 50 e8???????? 8b4514 }
            // n = 7, score = 300
            //   51                   | push                ecx
            //   0f8293000000         | jb                  0x99
            //   8b1e                 | mov                 ebx, dword ptr [esi]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]

        $sequence_7 = { 2432 2832 40 32443248 325032 683278327c 3280329832a8 }
            // n = 7, score = 300
            //   2432                 | and                 al, 0x32
            //   2832                 | sub                 byte ptr [edx], dh
            //   40                   | inc                 eax
            //   32443248             | xor                 al, byte ptr [edx + esi + 0x48]
            //   325032               | xor                 dl, byte ptr [eax + 0x32]
            //   683278327c           | push                0x7c327832
            //   3280329832a8         | xor                 al, byte ptr [eax - 0x57cd67ce]

        $sequence_8 = { 50 c6450b00 e8???????? 8b0e 8d450b 6a01 50 }
            // n = 7, score = 300
            //   50                   | push                eax
            //   c6450b00             | mov                 byte ptr [ebp + 0xb], 0
            //   e8????????           |                     
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   8d450b               | lea                 eax, [ebp + 0xb]
            //   6a01                 | push                1
            //   50                   | push                eax

        $sequence_9 = { e8???????? 8bf0 895f10 8b45fc 8bcb 894714 8bfe }
            // n = 7, score = 300
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   895f10               | mov                 dword ptr [edi + 0x10], ebx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8bcb                 | mov                 ecx, ebx
            //   894714               | mov                 dword ptr [edi + 0x14], eax
            //   8bfe                 | mov                 edi, esi

    condition:
        7 of them and filesize < 1482752
}