rule win_deathransom_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.deathransom."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.deathransom"
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
        $sequence_0 = { 8b55d8 33c3 03c1 81c216c1a419 03d0 8bcf 0155ec }
            // n = 7, score = 100
            //   8b55d8               | mov                 edx, dword ptr [ebp - 0x28]
            //   33c3                 | xor                 eax, ebx
            //   03c1                 | add                 eax, ecx
            //   81c216c1a419         | add                 edx, 0x19a4c116
            //   03d0                 | add                 edx, eax
            //   8bcf                 | mov                 ecx, edi
            //   0155ec               | add                 dword ptr [ebp - 0x14], edx

        $sequence_1 = { 7905 83c9ff eb1c 7e04 8b06 eb02 33c0 }
            // n = 7, score = 100
            //   7905                 | jns                 7
            //   83c9ff               | or                  ecx, 0xffffffff
            //   eb1c                 | jmp                 0x1e
            //   7e04                 | jle                 6
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax

        $sequence_2 = { 7414 ff75ec 6a00 ff15???????? 50 }
            // n = 5, score = 100
            //   7414                 | je                  0x16
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   50                   | push                eax

        $sequence_3 = { 2bd9 660f1f440000 8b0c13 8d5204 }
            // n = 4, score = 100
            //   2bd9                 | sub                 ebx, ecx
            //   660f1f440000         | nop                 word ptr [eax + eax]
            //   8b0c13               | mov                 ecx, dword ptr [ebx + edx]
            //   8d5204               | lea                 edx, [edx + 4]

        $sequence_4 = { c1e818 83e63f 8845f8 8bc1 }
            // n = 4, score = 100
            //   c1e818               | shr                 eax, 0x18
            //   83e63f               | and                 esi, 0x3f
            //   8845f8               | mov                 byte ptr [ebp - 8], al
            //   8bc1                 | mov                 eax, ecx

        $sequence_5 = { 0bc8 0fb6421c c1e108 8d55c0 0bc8 0fbe05???????? 894df8 }
            // n = 7, score = 100
            //   0bc8                 | or                  ecx, eax
            //   0fb6421c             | movzx               eax, byte ptr [edx + 0x1c]
            //   c1e108               | shl                 ecx, 8
            //   8d55c0               | lea                 edx, [ebp - 0x40]
            //   0bc8                 | or                  ecx, eax
            //   0fbe05????????       |                     
            //   894df8               | mov                 dword ptr [ebp - 8], ecx

        $sequence_6 = { c3 8b4908 f7d6 8b7a08 85f6 78ef 8d04b1 }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   8b4908               | mov                 ecx, dword ptr [ecx + 8]
            //   f7d6                 | not                 esi
            //   8b7a08               | mov                 edi, dword ptr [edx + 8]
            //   85f6                 | test                esi, esi
            //   78ef                 | js                  0xfffffff1
            //   8d04b1               | lea                 eax, [ecx + esi*4]

        $sequence_7 = { 57 ff15???????? 8b1d???????? 83c410 6a00 6880000000 6a01 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8b1d????????         |                     
            //   83c410               | add                 esp, 0x10
            //   6a00                 | push                0
            //   6880000000           | push                0x80
            //   6a01                 | push                1

        $sequence_8 = { 0fb6f2 8ac8 c0e907 0fb6c9 }
            // n = 4, score = 100
            //   0fb6f2               | movzx               esi, dl
            //   8ac8                 | mov                 cl, al
            //   c0e907               | shr                 cl, 7
            //   0fb6c9               | movzx               ecx, cl

        $sequence_9 = { 83c40c c78530ffffff01000000 8d8538ffffff c78534ffffff00000000 6890000000 6a00 }
            // n = 6, score = 100
            //   83c40c               | add                 esp, 0xc
            //   c78530ffffff01000000     | mov    dword ptr [ebp - 0xd0], 1
            //   8d8538ffffff         | lea                 eax, [ebp - 0xc8]
            //   c78534ffffff00000000     | mov    dword ptr [ebp - 0xcc], 0
            //   6890000000           | push                0x90
            //   6a00                 | push                0

    condition:
        7 of them and filesize < 133120
}