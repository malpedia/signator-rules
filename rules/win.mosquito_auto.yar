rule win_mosquito_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.mosquito."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mosquito"
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
        $sequence_0 = { e8???????? 6a20 8bf0 e8???????? }
            // n = 4, score = 400
            //   e8????????           |                     
            //   6a20                 | push                0x20
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     

        $sequence_1 = { 8bfc f3a5 ff942464020000 81c450020000 85c0 }
            // n = 5, score = 400
            //   8bfc                 | mov                 edi, esp
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   ff942464020000       | call                dword ptr [esp + 0x264]
            //   81c450020000         | add                 esp, 0x250
            //   85c0                 | test                eax, eax

        $sequence_2 = { 52 50 6a00 6801c1fd7d }
            // n = 4, score = 400
            //   52                   | push                edx
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6801c1fd7d           | push                0x7dfdc101

        $sequence_3 = { f7d8 1bc0 83e0b4 83c04c }
            // n = 4, score = 400
            //   f7d8                 | neg                 eax
            //   1bc0                 | sbb                 eax, eax
            //   83e0b4               | and                 eax, 0xffffffb4
            //   83c04c               | add                 eax, 0x4c

        $sequence_4 = { 8b4904 894b04 8bcc 57 }
            // n = 4, score = 300
            //   8b4904               | mov                 ecx, dword ptr [ecx + 4]
            //   894b04               | mov                 dword ptr [ebx + 4], ecx
            //   8bcc                 | mov                 ecx, esp
            //   57                   | push                edi

        $sequence_5 = { 8b4104 894704 8bc2 e9???????? ba00004006 8bc1 3bca }
            // n = 7, score = 300
            //   8b4104               | mov                 eax, dword ptr [ecx + 4]
            //   894704               | mov                 dword ptr [edi + 4], eax
            //   8bc2                 | mov                 eax, edx
            //   e9????????           |                     
            //   ba00004006           | mov                 edx, 0x6400000
            //   8bc1                 | mov                 eax, ecx
            //   3bca                 | cmp                 ecx, edx

        $sequence_6 = { 8bcf e8???????? 50 e8???????? 59 8bf0 8bcf }
            // n = 7, score = 300
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8bf0                 | mov                 esi, eax
            //   8bcf                 | mov                 ecx, edi

        $sequence_7 = { 8bfc f3a5 ff942460020000 81c450020000 }
            // n = 4, score = 300
            //   8bfc                 | mov                 edi, esp
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   ff942460020000       | call                dword ptr [esp + 0x260]
            //   81c450020000         | add                 esp, 0x250

        $sequence_8 = { b883000000 e9???????? 8b4f38 8d55f4 8365fc00 }
            // n = 5, score = 300
            //   b883000000           | mov                 eax, 0x83
            //   e9????????           |                     
            //   8b4f38               | mov                 ecx, dword ptr [edi + 0x38]
            //   8d55f4               | lea                 edx, [ebp - 0xc]
            //   8365fc00             | and                 dword ptr [ebp - 4], 0

        $sequence_9 = { e8???????? 6a20 e8???????? 83c40c }
            // n = 4, score = 300
            //   e8????????           |                     
            //   6a20                 | push                0x20
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_10 = { 6a00 ff15???????? 6a00 56 ff15???????? 8903 83f8ff }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8903                 | mov                 dword ptr [ebx], eax
            //   83f8ff               | cmp                 eax, -1

        $sequence_11 = { 0000 006500 676c 0010 }
            // n = 4, score = 200
            //   0000                 | add                 byte ptr [eax], al
            //   006500               | add                 byte ptr [ebp], ah
            //   676c                 | insb                byte ptr es:[di], dx
            //   0010                 | add                 byte ptr [eax], dl

        $sequence_12 = { 0000 0018 a0???????? 57 }
            // n = 4, score = 200
            //   0000                 | add                 byte ptr [eax], al
            //   0018                 | add                 byte ptr [eax], bl
            //   a0????????           |                     
            //   57                   | push                edi

        $sequence_13 = { 0000 006301 1000 7500 }
            // n = 4, score = 200
            //   0000                 | add                 byte ptr [eax], al
            //   006301               | add                 byte ptr [ebx + 1], ah
            //   1000                 | adc                 byte ptr [eax], al
            //   7500                 | jne                 2

        $sequence_14 = { 0000 00645657 8b7dc2 0400 }
            // n = 4, score = 200
            //   0000                 | add                 byte ptr [eax], al
            //   00645657             | add                 byte ptr [esi + edx*2 + 0x57], ah
            //   8b7dc2               | mov                 edi, dword ptr [ebp - 0x3e]
            //   0400                 | add                 al, 0

        $sequence_15 = { 6801c1fd7d e8???????? 8bd8 eb02 }
            // n = 4, score = 200
            //   6801c1fd7d           | push                0x7dfdc101
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   eb02                 | jmp                 4

        $sequence_16 = { 0000 0001 1001 c550f0 8b8078005900 }
            // n = 5, score = 200
            //   0000                 | add                 byte ptr [eax], al
            //   0001                 | add                 byte ptr [ecx], al
            //   1001                 | adc                 byte ptr [ecx], al
            //   c550f0               | lds                 edx, ptr [eax - 0x10]
            //   8b8078005900         | mov                 eax, dword ptr [eax + 0x590078]

        $sequence_17 = { 0000 0032 08804d086440 5e }
            // n = 4, score = 200
            //   0000                 | add                 byte ptr [eax], al
            //   0032                 | add                 byte ptr [edx], dh
            //   08804d086440         | or                  byte ptr [eax + 0x4064084d], al
            //   5e                   | pop                 esi

        $sequence_18 = { 6c 5e 8b00 6500c7 4d 0800 }
            // n = 6, score = 200
            //   6c                   | insb                byte ptr es:[edi], dx
            //   5e                   | pop                 esi
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   6500c7               | add                 bh, al
            //   4d                   | dec                 ebp
            //   0800                 | or                  byte ptr [eax], al

        $sequence_19 = { 0000 00748078 3001 40 }
            // n = 4, score = 200
            //   0000                 | add                 byte ptr [eax], al
            //   00748078             | add                 byte ptr [eax + eax*4 + 0x78], dh
            //   3001                 | xor                 byte ptr [ecx], al
            //   40                   | inc                 eax

    condition:
        7 of them and filesize < 1015808
}