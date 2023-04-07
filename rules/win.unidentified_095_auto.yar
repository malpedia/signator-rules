rule win_unidentified_095_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.unidentified_095."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_095"
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
        $sequence_0 = { 4533c0 4889442420 498bcc ff15???????? 85c0 0f85d4000000 3975ab }
            // n = 7, score = 100
            //   4533c0               | dec                 eax
            //   4889442420           | test                eax, eax
            //   498bcc               | je                  0x1418
            //   ff15????????         |                     
            //   85c0                 | dec                 esp
            //   0f85d4000000         | lea                 ecx, [esp + 0x20]
            //   3975ab               | inc                 ebp

        $sequence_1 = { ff15???????? 8bf8 4d85e4 7409 498bcc ff15???????? 488b4d97 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8bf8                 | inc                 ecx
            //   4d85e4               | mov                 eax, 0xf402
            //   7409                 | inc                 esp
            //   498bcc               | movaps              xmmword ptr [esp + 0x50], xmm0
            //   ff15????????         |                     
            //   488b4d97             | inc                 esp

        $sequence_2 = { 7622 498bc9 488d159b1c0100 498bc1 }
            // n = 4, score = 100
            //   7622                 | dec                 eax
            //   498bc9               | lea                 edi, [0x14441]
            //   488d159b1c0100       | jmp                 0xc8c
            //   498bc1               | dec                 eax

        $sequence_3 = { 7405 bf01000000 ff15???????? 8be8 4885db 7409 488bcb }
            // n = 7, score = 100
            //   7405                 | ret                 
            //   bf01000000           | dec                 eax
            //   ff15????????         |                     
            //   8be8                 | mov                 dword ptr [esp + 8], edi
            //   4885db               | dec                 eax
            //   7409                 | lea                 edi, [0x1997c]
            //   488bcb               | dec                 eax

        $sequence_4 = { 660f1f440000 48ffc0 66833c4200 75f6 48ffc0 41b800040000 }
            // n = 6, score = 100
            //   660f1f440000         | dec                 eax
            //   48ffc0               | mov                 ecx, ebx
            //   66833c4200           | test                eax, eax
            //   75f6                 | je                  0x149e
            //   48ffc0               | dec                 eax
            //   41b800040000         | mov                 edx, esi

        $sequence_5 = { 0f84e3000000 4883cfff 488bdf 48ffc3 4138341e 75f7 ffc3 }
            // n = 7, score = 100
            //   0f84e3000000         | lea                 ecx, [0x1a579]
            //   4883cfff             | dec                 eax
            //   488bdf               | lea                 ecx, [0x1a585]
            //   48ffc3               | mov                 al, 1
            //   4138341e             | dec                 eax
            //   75f7                 | sub                 esp, 0x28
            //   ffc3                 | dec                 eax

        $sequence_6 = { 894c2428 488d156a4f0100 4889442420 e8???????? e9???????? 89758f e9???????? }
            // n = 7, score = 100
            //   894c2428             | dec                 eax
            //   488d156a4f0100       | add                 esp, 0x48
            //   4889442420           | inc                 ecx
            //   e8????????           |                     
            //   e9????????           |                     
            //   89758f               | pop                 ebp
            //   e9????????           |                     

        $sequence_7 = { 751f ff15???????? 8bd0 488d0d664e0100 e8???????? }
            // n = 5, score = 100
            //   751f                 | mov                 ebp, ecx
            //   ff15????????         |                     
            //   8bd0                 | xor                 edi, edi
            //   488d0d664e0100       | xor                 ecx, ecx
            //   e8????????           |                     

        $sequence_8 = { e8???????? 85c0 7509 c7459f01000000 eb09 39759f 0f8e88010000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   85c0                 | dec                 eax
            //   7509                 | add                 esp, 0x48
            //   c7459f01000000       | ret                 
            //   eb09                 | xor                 eax, eax
            //   39759f               | inc                 eax
            //   0f8e88010000         | setne               bh

        $sequence_9 = { 488bd5 488bcb e8???????? 85c0 7507 41c70601000000 488bcb }
            // n = 7, score = 100
            //   488bd5               | dec                 eax
            //   488bcb               | mov                 ebx, dword ptr [esp + 0xa0]
            //   e8????????           |                     
            //   85c0                 | xor                 eax, eax
            //   7507                 | dec                 eax
            //   41c70601000000       | mov                 ecx, dword ptr [esp + 0x38]
            //   488bcb               | dec                 esp

    condition:
        7 of them and filesize < 339968
}