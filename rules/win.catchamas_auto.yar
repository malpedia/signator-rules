rule win_catchamas_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.catchamas."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.catchamas"
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
        $sequence_0 = { 75f1 8b442418 668b4816 e8???????? }
            // n = 4, score = 200
            //   75f1                 | jne                 0xfffffff3
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]
            //   668b4816             | mov                 cx, word ptr [eax + 0x16]
            //   e8????????           |                     

        $sequence_1 = { 68???????? 85c0 7449 0fb7542418 8d44246c }
            // n = 5, score = 200
            //   68????????           |                     
            //   85c0                 | test                eax, eax
            //   7449                 | je                  0x4b
            //   0fb7542418           | movzx               edx, word ptr [esp + 0x18]
            //   8d44246c             | lea                 eax, [esp + 0x6c]

        $sequence_2 = { 83c40c c3 b801000000 6a0c 50 8d542410 }
            // n = 6, score = 200
            //   83c40c               | add                 esp, 0xc
            //   c3                   | ret                 
            //   b801000000           | mov                 eax, 1
            //   6a0c                 | push                0xc
            //   50                   | push                eax
            //   8d542410             | lea                 edx, [esp + 0x10]

        $sequence_3 = { 5f 66894e14 5e 8b8c2404080000 }
            // n = 4, score = 200
            //   5f                   | pop                 edi
            //   66894e14             | mov                 word ptr [esi + 0x14], cx
            //   5e                   | pop                 esi
            //   8b8c2404080000       | mov                 ecx, dword ptr [esp + 0x804]

        $sequence_4 = { 68???????? 50 ff15???????? 83c42c e9???????? }
            // n = 5, score = 200
            //   68????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c42c               | add                 esp, 0x2c
            //   e9????????           |                     

        $sequence_5 = { 8b0d???????? 68f1070000 89842478080000 89942474080000 8a15???????? 8d842481080000 }
            // n = 6, score = 200
            //   8b0d????????         |                     
            //   68f1070000           | push                0x7f1
            //   89842478080000       | mov                 dword ptr [esp + 0x878], eax
            //   89942474080000       | mov                 dword ptr [esp + 0x874], edx
            //   8a15????????         |                     
            //   8d842481080000       | lea                 eax, [esp + 0x881]

        $sequence_6 = { 8b8c2404080000 33cc e8???????? 81c408080000 c3 8d44240c 8bd0 }
            // n = 7, score = 200
            //   8b8c2404080000       | mov                 ecx, dword ptr [esp + 0x804]
            //   33cc                 | xor                 ecx, esp
            //   e8????????           |                     
            //   81c408080000         | add                 esp, 0x808
            //   c3                   | ret                 
            //   8d44240c             | lea                 eax, [esp + 0xc]
            //   8bd0                 | mov                 edx, eax

        $sequence_7 = { 75fa 8818 8d842428020000 48 8a4801 }
            // n = 5, score = 200
            //   75fa                 | jne                 0xfffffffc
            //   8818                 | mov                 byte ptr [eax], bl
            //   8d842428020000       | lea                 eax, [esp + 0x228]
            //   48                   | dec                 eax
            //   8a4801               | mov                 cl, byte ptr [eax + 1]

        $sequence_8 = { 57 52 68ff000000 50 ff15???????? 33c0 }
            // n = 6, score = 200
            //   57                   | push                edi
            //   52                   | push                edx
            //   68ff000000           | push                0xff
            //   50                   | push                eax
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax

        $sequence_9 = { 8b4204 ffd0 834424184c 03f3 3bb4244c010000 0f8207ffffff }
            // n = 6, score = 200
            //   8b4204               | mov                 eax, dword ptr [edx + 4]
            //   ffd0                 | call                eax
            //   834424184c           | add                 dword ptr [esp + 0x18], 0x4c
            //   03f3                 | add                 esi, ebx
            //   3bb4244c010000       | cmp                 esi, dword ptr [esp + 0x14c]
            //   0f8207ffffff         | jb                  0xffffff0d

    condition:
        7 of them and filesize < 368640
}