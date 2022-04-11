rule win_comlook_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.comlook."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.comlook"
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
        $sequence_0 = { ff15???????? 83c404 3bf4 e8???????? 837de800 0f859f020000 c745cc00000000 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4
            //   3bf4                 | cmp                 esi, esp
            //   e8????????           |                     
            //   837de800             | cmp                 dword ptr [ebp - 0x18], 0
            //   0f859f020000         | jne                 0x2a5
            //   c745cc00000000       | mov                 dword ptr [ebp - 0x34], 0

        $sequence_1 = { 8b857cffffff 50 e8???????? 83c40c 8b4dfc 3b8df0feffff 7509 }
            // n = 7, score = 100
            //   8b857cffffff         | mov                 eax, dword ptr [ebp - 0x84]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   3b8df0feffff         | cmp                 ecx, dword ptr [ebp - 0x110]
            //   7509                 | jne                 0xb

        $sequence_2 = { 8b8850070000 51 8b5508 52 e8???????? 83c418 6a02 }
            // n = 7, score = 100
            //   8b8850070000         | mov                 ecx, dword ptr [eax + 0x750]
            //   51                   | push                ecx
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   6a02                 | push                2

        $sequence_3 = { e9???????? 8d7dc0 e9???????? 8b7dec e9???????? 8b7de8 e9???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8d7dc0               | lea                 edi, dword ptr [ebp - 0x40]
            //   e9????????           |                     
            //   8b7dec               | mov                 edi, dword ptr [ebp - 0x14]
            //   e9????????           |                     
            //   8b7de8               | mov                 edi, dword ptr [ebp - 0x18]
            //   e9????????           |                     

        $sequence_4 = { 8b4608 3b4620 741f e8???????? 80385c 7510 8bce }
            // n = 7, score = 100
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   3b4620               | cmp                 eax, dword ptr [esi + 0x20]
            //   741f                 | je                  0x21
            //   e8????????           |                     
            //   80385c               | cmp                 byte ptr [eax], 0x5c
            //   7510                 | jne                 0x12
            //   8bce                 | mov                 ecx, esi

        $sequence_5 = { 8b5508 52 e8???????? 83c404 034508 8945fc 837df800 }
            // n = 7, score = 100
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   034508               | add                 eax, dword ptr [ebp + 8]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   837df800             | cmp                 dword ptr [ebp - 8], 0

        $sequence_6 = { eb0e 895008 8b4f08 3b4108 7503 895108 8b4a04 }
            // n = 7, score = 100
            //   eb0e                 | jmp                 0x10
            //   895008               | mov                 dword ptr [eax + 8], edx
            //   8b4f08               | mov                 ecx, dword ptr [edi + 8]
            //   3b4108               | cmp                 eax, dword ptr [ecx + 8]
            //   7503                 | jne                 5
            //   895108               | mov                 dword ptr [ecx + 8], edx
            //   8b4a04               | mov                 ecx, dword ptr [edx + 4]

        $sequence_7 = { ffd0 83c40c 85c0 7817 85ed 7413 57 }
            // n = 7, score = 100
            //   ffd0                 | call                eax
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   7817                 | js                  0x19
            //   85ed                 | test                ebp, ebp
            //   7413                 | je                  0x15
            //   57                   | push                edi

        $sequence_8 = { eb75 8d4d94 51 c645fc02 e8???????? c645fc01 837de810 }
            // n = 7, score = 100
            //   eb75                 | jmp                 0x77
            //   8d4d94               | lea                 ecx, dword ptr [ebp - 0x6c]
            //   51                   | push                ecx
            //   c645fc02             | mov                 byte ptr [ebp - 4], 2
            //   e8????????           |                     
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   837de810             | cmp                 dword ptr [ebp - 0x18], 0x10

        $sequence_9 = { f7431400400000 8b7508 8a4518 89742428 895c242c 88442414 7540 }
            // n = 7, score = 100
            //   f7431400400000       | test                dword ptr [ebx + 0x14], 0x4000
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   8a4518               | mov                 al, byte ptr [ebp + 0x18]
            //   89742428             | mov                 dword ptr [esp + 0x28], esi
            //   895c242c             | mov                 dword ptr [esp + 0x2c], ebx
            //   88442414             | mov                 byte ptr [esp + 0x14], al
            //   7540                 | jne                 0x42

    condition:
        7 of them and filesize < 4553728
}