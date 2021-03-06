rule win_mozart_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.mozart."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mozart"
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
        $sequence_0 = { f644c80401 0f84ff000000 6a01 56 53 e8???????? 83c40c }
            // n = 7, score = 200
            //   f644c80401           | test                byte ptr [eax + ecx*8 + 4], 1
            //   0f84ff000000         | je                  0x105
            //   6a01                 | push                1
            //   56                   | push                esi
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_1 = { 7704 3bfd 7299 8b4c2418 8b7c2414 ff05???????? }
            // n = 6, score = 200
            //   7704                 | ja                  6
            //   3bfd                 | cmp                 edi, ebp
            //   7299                 | jb                  0xffffff9b
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]
            //   8b7c2414             | mov                 edi, dword ptr [esp + 0x14]
            //   ff05????????         |                     

        $sequence_2 = { 68ff0f1f00 ff15???????? 8bf8 85ff 0f84eb000000 }
            // n = 5, score = 200
            //   68ff0f1f00           | push                0x1f0fff
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi
            //   0f84eb000000         | je                  0xf1

        $sequence_3 = { 83f85a 7714 8088????????10 8ac8 80c120 888880ca4000 eb1f }
            // n = 7, score = 200
            //   83f85a               | cmp                 eax, 0x5a
            //   7714                 | ja                  0x16
            //   8088????????10       |                     
            //   8ac8                 | mov                 cl, al
            //   80c120               | add                 cl, 0x20
            //   888880ca4000         | mov                 byte ptr [eax + 0x40ca80], cl
            //   eb1f                 | jmp                 0x21

        $sequence_4 = { 7e12 393cb5f8c84000 0f84fe000000 46 3bf0 }
            // n = 5, score = 200
            //   7e12                 | jle                 0x14
            //   393cb5f8c84000       | cmp                 dword ptr [esi*4 + 0x40c8f8], edi
            //   0f84fe000000         | je                  0x104
            //   46                   | inc                 esi
            //   3bf0                 | cmp                 esi, eax

        $sequence_5 = { b9???????? 8bc2 c1f805 8b0485c0db4000 8bf2 83e61f }
            // n = 6, score = 200
            //   b9????????           |                     
            //   8bc2                 | mov                 eax, edx
            //   c1f805               | sar                 eax, 5
            //   8b0485c0db4000       | mov                 eax, dword ptr [eax*4 + 0x40dbc0]
            //   8bf2                 | mov                 esi, edx
            //   83e61f               | and                 esi, 0x1f

        $sequence_6 = { 83c40c 83f8ff 0f84d9000000 57 8b7d0c 2bf8 }
            // n = 6, score = 200
            //   83c40c               | add                 esp, 0xc
            //   83f8ff               | cmp                 eax, -1
            //   0f84d9000000         | je                  0xdf
            //   57                   | push                edi
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]
            //   2bf8                 | sub                 edi, eax

        $sequence_7 = { a801 7447 be00800000 2580000000 3974240c }
            // n = 5, score = 200
            //   a801                 | test                al, 1
            //   7447                 | je                  0x49
            //   be00800000           | mov                 esi, 0x8000
            //   2580000000           | and                 eax, 0x80
            //   3974240c             | cmp                 dword ptr [esp + 0xc], esi

        $sequence_8 = { 48 75f5 bf???????? c680f1ba400000 }
            // n = 4, score = 200
            //   48                   | dec                 eax
            //   75f5                 | jne                 0xfffffff7
            //   bf????????           |                     
            //   c680f1ba400000       | mov                 byte ptr [eax + 0x40baf1], 0

        $sequence_9 = { 42 c60200 8bc3 46 8d7801 8bff 8a08 }
            // n = 7, score = 200
            //   42                   | inc                 edx
            //   c60200               | mov                 byte ptr [edx], 0
            //   8bc3                 | mov                 eax, ebx
            //   46                   | inc                 esi
            //   8d7801               | lea                 edi, [eax + 1]
            //   8bff                 | mov                 edi, edi
            //   8a08                 | mov                 cl, byte ptr [eax]

    condition:
        7 of them and filesize < 114688
}