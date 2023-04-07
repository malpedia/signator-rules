rule win_final1stspy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.final1stspy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.final1stspy"
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
        $sequence_0 = { 6690 3acd 7412 8a4801 }
            // n = 4, score = 300
            //   6690                 | nop                 
            //   3acd                 | cmp                 cl, ch
            //   7412                 | je                  0x14
            //   8a4801               | mov                 cl, byte ptr [eax + 1]

        $sequence_1 = { 7410 8a11 8acb 3aca 7425 8a4801 }
            // n = 6, score = 300
            //   7410                 | je                  0x12
            //   8a11                 | mov                 dl, byte ptr [ecx]
            //   8acb                 | mov                 cl, bl
            //   3aca                 | cmp                 cl, dl
            //   7425                 | je                  0x27
            //   8a4801               | mov                 cl, byte ptr [eax + 1]

        $sequence_2 = { 81cf00feffff 47 33f6 85ff 7e0a e8???????? 46 }
            // n = 7, score = 300
            //   81cf00feffff         | or                  edi, 0xfffffe00
            //   47                   | inc                 edi
            //   33f6                 | xor                 esi, esi
            //   85ff                 | test                edi, edi
            //   7e0a                 | jle                 0xc
            //   e8????????           |                     
            //   46                   | inc                 esi

        $sequence_3 = { 7519 b8???????? 84db 7410 }
            // n = 4, score = 300
            //   7519                 | jne                 0x1b
            //   b8????????           |                     
            //   84db                 | test                bl, bl
            //   7410                 | je                  0x12

        $sequence_4 = { 8a4801 40 84c9 75f4 8b45f8 2bf0 56 }
            // n = 7, score = 300
            //   8a4801               | mov                 cl, byte ptr [eax + 1]
            //   40                   | inc                 eax
            //   84c9                 | test                cl, cl
            //   75f4                 | jne                 0xfffffff6
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   2bf0                 | sub                 esi, eax
            //   56                   | push                esi

        $sequence_5 = { 8bd6 0f281d???????? 2bd0 0f10040f }
            // n = 4, score = 300
            //   8bd6                 | mov                 edx, esi
            //   0f281d????????       |                     
            //   2bd0                 | sub                 edx, eax
            //   0f10040f             | movups              xmm0, xmmword ptr [edi + ecx]

        $sequence_6 = { 46 3bf7 7cf6 8b3d???????? 66660f1f840000000000 be00080000 }
            // n = 6, score = 300
            //   46                   | inc                 esi
            //   3bf7                 | cmp                 esi, edi
            //   7cf6                 | jl                  0xfffffff8
            //   8b3d????????         |                     
            //   66660f1f840000000000     | nop    word ptr [eax + eax]
            //   be00080000           | mov                 esi, 0x800

        $sequence_7 = { 8a1d???????? 33ff 90 85ff 7519 b8???????? 84db }
            // n = 7, score = 300
            //   8a1d????????         |                     
            //   33ff                 | xor                 edi, edi
            //   90                   | nop                 
            //   85ff                 | test                edi, edi
            //   7519                 | jne                 0x1b
            //   b8????????           |                     
            //   84db                 | test                bl, bl

        $sequence_8 = { 83ec0c 53 8bc1 8955f4 56 8bf0 8945fc }
            // n = 7, score = 300
            //   83ec0c               | sub                 esp, 0xc
            //   53                   | push                ebx
            //   8bc1                 | mov                 eax, ecx
            //   8955f4               | mov                 dword ptr [ebp - 0xc], edx
            //   56                   | push                esi
            //   8bf0                 | mov                 esi, eax
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_9 = { 7507 bf01000000 eb2b b8???????? 8acb }
            // n = 5, score = 300
            //   7507                 | jne                 9
            //   bf01000000           | mov                 edi, 1
            //   eb2b                 | jmp                 0x2d
            //   b8????????           |                     
            //   8acb                 | mov                 cl, bl

    condition:
        7 of them and filesize < 557056
}