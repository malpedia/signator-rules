rule win_evilgrab_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.evilgrab."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.evilgrab"
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
        $sequence_0 = { 52 6aaf 68???????? 8d95c0d2ffff 52 ffd6 83c41c }
            // n = 7, score = 200
            //   52                   | push                edx
            //   6aaf                 | push                -0x51
            //   68????????           |                     
            //   8d95c0d2ffff         | lea                 edx, dword ptr [ebp - 0x2d40]
            //   52                   | push                edx
            //   ffd6                 | call                esi
            //   83c41c               | add                 esp, 0x1c

        $sequence_1 = { 8bc8 33c0 83e103 6689ac24ac020000 f3a4 b9ff030000 8dbc24b5040000 }
            // n = 7, score = 200
            //   8bc8                 | mov                 ecx, eax
            //   33c0                 | xor                 eax, eax
            //   83e103               | and                 ecx, 3
            //   6689ac24ac020000     | mov                 word ptr [esp + 0x2ac], bp
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   b9ff030000           | mov                 ecx, 0x3ff
            //   8dbc24b5040000       | lea                 edi, dword ptr [esp + 0x4b5]

        $sequence_2 = { 83c410 6a00 6a00 8d9594a8ffff 52 6800040000 ff15???????? }
            // n = 7, score = 200
            //   83c410               | add                 esp, 0x10
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d9594a8ffff         | lea                 edx, dword ptr [ebp - 0x576c]
            //   52                   | push                edx
            //   6800040000           | push                0x400
            //   ff15????????         |                     

        $sequence_3 = { 8b4c241c 83c408 8d9424a41b0000 52 e8???????? 5f 5e }
            // n = 7, score = 200
            //   8b4c241c             | mov                 ecx, dword ptr [esp + 0x1c]
            //   83c408               | add                 esp, 8
            //   8d9424a41b0000       | lea                 edx, dword ptr [esp + 0x1ba4]
            //   52                   | push                edx
            //   e8????????           |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_4 = { e8???????? 8b4c2420 6a00 56 51 ff15???????? }
            // n = 6, score = 200
            //   e8????????           |                     
            //   8b4c2420             | mov                 ecx, dword ptr [esp + 0x20]
            //   6a00                 | push                0
            //   56                   | push                esi
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_5 = { 68???????? 51 ff15???????? 85c0 0f856e020000 8b35???????? 8d942414040000 }
            // n = 7, score = 200
            //   68????????           |                     
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f856e020000         | jne                 0x274
            //   8b35????????         |                     
            //   8d942414040000       | lea                 edx, dword ptr [esp + 0x414]

        $sequence_6 = { 896c2424 ff15???????? a1???????? 8b8c242c030000 8b1d???????? 55 }
            // n = 6, score = 200
            //   896c2424             | mov                 dword ptr [esp + 0x24], ebp
            //   ff15????????         |                     
            //   a1????????           |                     
            //   8b8c242c030000       | mov                 ecx, dword ptr [esp + 0x32c]
            //   8b1d????????         |                     
            //   55                   | push                ebp

        $sequence_7 = { 50 68???????? 8b0e 81c1d2000000 51 6802000080 }
            // n = 6, score = 200
            //   50                   | push                eax
            //   68????????           |                     
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   81c1d2000000         | add                 ecx, 0xd2
            //   51                   | push                ecx
            //   6802000080           | push                0x80000002

        $sequence_8 = { 50 ff5108 e9???????? 3c02 0f854f060000 8b4324 8d1440 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   ff5108               | call                dword ptr [ecx + 8]
            //   e9????????           |                     
            //   3c02                 | cmp                 al, 2
            //   0f854f060000         | jne                 0x655
            //   8b4324               | mov                 eax, dword ptr [ebx + 0x24]
            //   8d1440               | lea                 edx, dword ptr [eax + eax*2]

        $sequence_9 = { 3c30 7508 85f6 746e b029 eb6a 3c31 }
            // n = 7, score = 200
            //   3c30                 | cmp                 al, 0x30
            //   7508                 | jne                 0xa
            //   85f6                 | test                esi, esi
            //   746e                 | je                  0x70
            //   b029                 | mov                 al, 0x29
            //   eb6a                 | jmp                 0x6c
            //   3c31                 | cmp                 al, 0x31

    condition:
        7 of them and filesize < 327680
}