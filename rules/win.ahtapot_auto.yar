rule win_ahtapot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.ahtapot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ahtapot"
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
        $sequence_0 = { 6689845d9ed7ffff 0fbe45ea 66898c5da0d7ffff 0fbe4deb 6689945da2d7ffff 0fbe55ec 6689845da4d7ffff }
            // n = 7, score = 100
            //   6689845d9ed7ffff     | mov                 word ptr [ebp + ebx*2 - 0x2862], ax
            //   0fbe45ea             | movsx               eax, byte ptr [ebp - 0x16]
            //   66898c5da0d7ffff     | mov                 word ptr [ebp + ebx*2 - 0x2860], cx
            //   0fbe4deb             | movsx               ecx, byte ptr [ebp - 0x15]
            //   6689945da2d7ffff     | mov                 word ptr [ebp + ebx*2 - 0x285e], dx
            //   0fbe55ec             | movsx               edx, byte ptr [ebp - 0x14]
            //   6689845da4d7ffff     | mov                 word ptr [ebp + ebx*2 - 0x285c], ax

        $sequence_1 = { 81e1ff000000 33048d28a34200 81e2fdff0000 894638 8b4e3c 83ca02 }
            // n = 6, score = 100
            //   81e1ff000000         | and                 ecx, 0xff
            //   33048d28a34200       | xor                 eax, dword ptr [ecx*4 + 0x42a328]
            //   81e2fdff0000         | and                 edx, 0xfffd
            //   894638               | mov                 dword ptr [esi + 0x38], eax
            //   8b4e3c               | mov                 ecx, dword ptr [esi + 0x3c]
            //   83ca02               | or                  edx, 2

        $sequence_2 = { 8b4704 c7470c00000000 85c0 7409 807f0800 7403 50 }
            // n = 7, score = 100
            //   8b4704               | mov                 eax, dword ptr [edi + 4]
            //   c7470c00000000       | mov                 dword ptr [edi + 0xc], 0
            //   85c0                 | test                eax, eax
            //   7409                 | je                  0xb
            //   807f0800             | cmp                 byte ptr [edi + 8], 0
            //   7403                 | je                  5
            //   50                   | push                eax

        $sequence_3 = { 8d4900 46 668902 0fb70477 41 83c202 83f823 }
            // n = 7, score = 100
            //   8d4900               | lea                 ecx, [ecx]
            //   46                   | inc                 esi
            //   668902               | mov                 word ptr [edx], ax
            //   0fb70477             | movzx               eax, word ptr [edi + esi*2]
            //   41                   | inc                 ecx
            //   83c202               | add                 edx, 2
            //   83f823               | cmp                 eax, 0x23

        $sequence_4 = { 51 66898da8eeffff 8d8df0f6ffff 51 6a00 c78578eeffff44000000 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   66898da8eeffff       | mov                 word ptr [ebp - 0x1158], cx
            //   8d8df0f6ffff         | lea                 ecx, [ebp - 0x910]
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   c78578eeffff44000000     | mov    dword ptr [ebp - 0x1188], 0x44

        $sequence_5 = { 68???????? 51 ffd7 83c410 6a00 8d95f0fdffff 52 }
            // n = 7, score = 100
            //   68????????           |                     
            //   51                   | push                ecx
            //   ffd7                 | call                edi
            //   83c410               | add                 esp, 0x10
            //   6a00                 | push                0
            //   8d95f0fdffff         | lea                 edx, [ebp - 0x210]
            //   52                   | push                edx

        $sequence_6 = { bf???????? 89bc05d8c3ffff 51 89b540c4ffff e8???????? }
            // n = 5, score = 100
            //   bf????????           |                     
            //   89bc05d8c3ffff       | mov                 dword ptr [ebp + eax - 0x3c28], edi
            //   51                   | push                ecx
            //   89b540c4ffff         | mov                 dword ptr [ebp - 0x3bc0], esi
            //   e8????????           |                     

        $sequence_7 = { 53 8bce e8???????? c745fc02000000 8b07 8b4804 8d7710 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   c745fc02000000       | mov                 dword ptr [ebp - 4], 2
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   8d7710               | lea                 esi, [edi + 0x10]

        $sequence_8 = { 6a00 8d95c4fdffff 52 6a00 }
            // n = 4, score = 100
            //   6a00                 | push                0
            //   8d95c4fdffff         | lea                 edx, [ebp - 0x23c]
            //   52                   | push                edx
            //   6a00                 | push                0

        $sequence_9 = { 83f8ff 0f8430010000 8db5f0fdffff e8???????? 85c0 7542 8bd6 }
            // n = 7, score = 100
            //   83f8ff               | cmp                 eax, -1
            //   0f8430010000         | je                  0x136
            //   8db5f0fdffff         | lea                 esi, [ebp - 0x210]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7542                 | jne                 0x44
            //   8bd6                 | mov                 edx, esi

    condition:
        7 of them and filesize < 430080
}