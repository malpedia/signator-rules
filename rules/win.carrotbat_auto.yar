rule win_carrotbat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.carrotbat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.carrotbat"
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
        $sequence_0 = { 8b7c2404 66c1c60c 8b742408 f6d7 33cd f7d3 }
            // n = 6, score = 100
            //   8b7c2404             | mov                 edi, dword ptr [esp + 4]
            //   66c1c60c             | rol                 si, 0xc
            //   8b742408             | mov                 esi, dword ptr [esp + 8]
            //   f6d7                 | not                 bh
            //   33cd                 | xor                 ecx, ebp
            //   f7d3                 | not                 ebx

        $sequence_1 = { 8f442434 51 887c2404 66890424 890424 }
            // n = 5, score = 100
            //   8f442434             | pop                 dword ptr [esp + 0x34]
            //   51                   | push                ecx
            //   887c2404             | mov                 byte ptr [esp + 4], bh
            //   66890424             | mov                 word ptr [esp], ax
            //   890424               | mov                 dword ptr [esp], eax

        $sequence_2 = { 8b0c8d20ee4000 8d440104 8020fe ff36 e8???????? 59 }
            // n = 6, score = 100
            //   8b0c8d20ee4000       | mov                 ecx, dword ptr [ecx*4 + 0x40ee20]
            //   8d440104             | lea                 eax, [ecx + eax + 4]
            //   8020fe               | and                 byte ptr [eax], 0xfe
            //   ff36                 | push                dword ptr [esi]
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_3 = { c3 8bff 56 57 33f6 bf???????? 833cf5a4d5400001 }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   8bff                 | mov                 edi, edi
            //   56                   | push                esi
            //   57                   | push                edi
            //   33f6                 | xor                 esi, esi
            //   bf????????           |                     
            //   833cf5a4d5400001     | cmp                 dword ptr [esi*8 + 0x40d5a4], 1

        $sequence_4 = { 8b0c8d20ee4000 c1e006 8d440104 8020fe ff36 }
            // n = 5, score = 100
            //   8b0c8d20ee4000       | mov                 ecx, dword ptr [ecx*4 + 0x40ee20]
            //   c1e006               | shl                 eax, 6
            //   8d440104             | lea                 eax, [ecx + eax + 4]
            //   8020fe               | and                 byte ptr [eax], 0xfe
            //   ff36                 | push                dword ptr [esi]

        $sequence_5 = { c1f805 8d3c8520ee4000 8bf3 83e61f c1e606 8b07 0fbe440604 }
            // n = 7, score = 100
            //   c1f805               | sar                 eax, 5
            //   8d3c8520ee4000       | lea                 edi, [eax*4 + 0x40ee20]
            //   8bf3                 | mov                 esi, ebx
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   0fbe440604           | movsx               eax, byte ptr [esi + eax + 4]

        $sequence_6 = { 888c05f4fdffff 40 84c9 75ed 8d85f8feffff 6a5c }
            // n = 6, score = 100
            //   888c05f4fdffff       | mov                 byte ptr [ebp + eax - 0x20c], cl
            //   40                   | inc                 eax
            //   84c9                 | test                cl, cl
            //   75ed                 | jne                 0xffffffef
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]
            //   6a5c                 | push                0x5c

        $sequence_7 = { 50 66a5 ff15???????? 6810270000 ff15???????? }
            // n = 5, score = 100
            //   50                   | push                eax
            //   66a5                 | movsw               word ptr es:[edi], word ptr [esi]
            //   ff15????????         |                     
            //   6810270000           | push                0x2710
            //   ff15????????         |                     

        $sequence_8 = { 5b c21000 ff25???????? c705????????6ca14000 }
            // n = 4, score = 100
            //   5b                   | pop                 ebx
            //   c21000               | ret                 0x10
            //   ff25????????         |                     
            //   c705????????6ca14000     |     

        $sequence_9 = { 8f442434 9c 57 ff74243c c24000 686d3f4f6e }
            // n = 6, score = 100
            //   8f442434             | pop                 dword ptr [esp + 0x34]
            //   9c                   | pushfd              
            //   57                   | push                edi
            //   ff74243c             | push                dword ptr [esp + 0x3c]
            //   c24000               | ret                 0x40
            //   686d3f4f6e           | push                0x6e4f3f6d

    condition:
        7 of them and filesize < 360448
}