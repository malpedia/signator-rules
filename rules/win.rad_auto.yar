rule win_rad_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.rad."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rad"
        malpedia_rule_date = "20220405"
        malpedia_hash = "ecd38294bd47d5589be5cd5490dc8bb4804afc2a"
        malpedia_version = ""
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
        $sequence_0 = { 895c2478 895c247c c784248000000000040000 e8???????? 83c404 89842480000000 53 }
            // n = 7, score = 100
            //   895c2478             | mov                 dword ptr [esp + 0x78], ebx
            //   895c247c             | mov                 dword ptr [esp + 0x7c], ebx
            //   c784248000000000040000     | mov    dword ptr [esp + 0x80], 0x400
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   89842480000000       | mov                 dword ptr [esp + 0x80], eax
            //   53                   | push                ebx

        $sequence_1 = { ff15???????? 68???????? 8d442408 50 c744240cccec4000 e8???????? c6465801 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   68????????           |                     
            //   8d442408             | lea                 eax, dword ptr [esp + 8]
            //   50                   | push                eax
            //   c744240cccec4000     | mov                 dword ptr [esp + 0xc], 0x40eccc
            //   e8????????           |                     
            //   c6465801             | mov                 byte ptr [esi + 0x58], 1

        $sequence_2 = { 8d4dd0 83c008 51 50 e8???????? 50 }
            // n = 6, score = 100
            //   8d4dd0               | lea                 ecx, dword ptr [ebp - 0x30]
            //   83c008               | add                 eax, 8
            //   51                   | push                ecx
            //   50                   | push                eax
            //   e8????????           |                     
            //   50                   | push                eax

        $sequence_3 = { e8???????? 8d442420 50 8d8c2498000000 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   8d442420             | lea                 eax, dword ptr [esp + 0x20]
            //   50                   | push                eax
            //   8d8c2498000000       | lea                 ecx, dword ptr [esp + 0x98]

        $sequence_4 = { 8b550c 8908 8d4808 895004 85c9 740a 8b16 }
            // n = 7, score = 100
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   8908                 | mov                 dword ptr [eax], ecx
            //   8d4808               | lea                 ecx, dword ptr [eax + 8]
            //   895004               | mov                 dword ptr [eax + 4], edx
            //   85c9                 | test                ecx, ecx
            //   740a                 | je                  0xc
            //   8b16                 | mov                 edx, dword ptr [esi]

        $sequence_5 = { 8d45f4 64a300000000 8965f0 33ff 6a01 894da8 897dfc }
            // n = 7, score = 100
            //   8d45f4               | lea                 eax, dword ptr [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8965f0               | mov                 dword ptr [ebp - 0x10], esp
            //   33ff                 | xor                 edi, edi
            //   6a01                 | push                1
            //   894da8               | mov                 dword ptr [ebp - 0x58], ecx
            //   897dfc               | mov                 dword ptr [ebp - 4], edi

        $sequence_6 = { 8d442418 50 8d8c2420040000 51 c784244006000007000000 ff15???????? 83c408 }
            // n = 7, score = 100
            //   8d442418             | lea                 eax, dword ptr [esp + 0x18]
            //   50                   | push                eax
            //   8d8c2420040000       | lea                 ecx, dword ptr [esp + 0x420]
            //   51                   | push                ecx
            //   c784244006000007000000     | mov    dword ptr [esp + 0x640], 7
            //   ff15????????         |                     
            //   83c408               | add                 esp, 8

        $sequence_7 = { e8???????? 6a00 c645fc08 8b85e0fcffff 8b8ddcfcffff 68e8030000 50 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   6a00                 | push                0
            //   c645fc08             | mov                 byte ptr [ebp - 4], 8
            //   8b85e0fcffff         | mov                 eax, dword ptr [ebp - 0x320]
            //   8b8ddcfcffff         | mov                 ecx, dword ptr [ebp - 0x324]
            //   68e8030000           | push                0x3e8
            //   50                   | push                eax

        $sequence_8 = { 85c0 7507 c605????????01 c745fcffffffff }
            // n = 4, score = 100
            //   85c0                 | test                eax, eax
            //   7507                 | jne                 9
            //   c605????????01       |                     
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff

        $sequence_9 = { 89543970 8b476c 8d7708 50 c706???????? ff15???????? 83c404 }
            // n = 7, score = 100
            //   89543970             | mov                 dword ptr [ecx + edi + 0x70], edx
            //   8b476c               | mov                 eax, dword ptr [edi + 0x6c]
            //   8d7708               | lea                 esi, dword ptr [edi + 8]
            //   50                   | push                eax
            //   c706????????         |                     
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4

    condition:
        7 of them and filesize < 207872
}