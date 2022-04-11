rule win_redsalt_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.redsalt."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redsalt"
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
        $sequence_0 = { 83c414 33c9 83f8ff 0f95c1 }
            // n = 4, score = 1100
            //   83c414               | add                 esp, 0x14
            //   33c9                 | xor                 ecx, ecx
            //   83f8ff               | cmp                 eax, -1
            //   0f95c1               | setne               cl

        $sequence_1 = { 750b 68e8030000 ff15???????? e8???????? }
            // n = 4, score = 1100
            //   750b                 | jne                 0xd
            //   68e8030000           | push                0x3e8
            //   ff15????????         |                     
            //   e8????????           |                     

        $sequence_2 = { e8???????? 85c0 750a 6a32 }
            // n = 4, score = 900
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   750a                 | jne                 0xc
            //   6a32                 | push                0x32

        $sequence_3 = { c745d060ea0000 6a04 8d45d0 50 6806100000 68ffff0000 }
            // n = 6, score = 900
            //   c745d060ea0000       | mov                 dword ptr [ebp - 0x30], 0xea60
            //   6a04                 | push                4
            //   8d45d0               | lea                 eax, dword ptr [ebp - 0x30]
            //   50                   | push                eax
            //   6806100000           | push                0x1006
            //   68ffff0000           | push                0xffff

        $sequence_4 = { 85c0 7515 c705????????01000000 ff15???????? e9???????? }
            // n = 5, score = 900
            //   85c0                 | test                eax, eax
            //   7515                 | jne                 0x17
            //   c705????????01000000     |     
            //   ff15????????         |                     
            //   e9????????           |                     

        $sequence_5 = { 51 ffd6 85c0 7510 }
            // n = 4, score = 900
            //   51                   | push                ecx
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   7510                 | jne                 0x12

        $sequence_6 = { 83c9ff 85f6 7c0e 83fe7f }
            // n = 4, score = 800
            //   83c9ff               | or                  ecx, 0xffffffff
            //   85f6                 | test                esi, esi
            //   7c0e                 | jl                  0x10
            //   83fe7f               | cmp                 esi, 0x7f

        $sequence_7 = { 8b5508 52 e8???????? 83c414 6a00 6a01 }
            // n = 6, score = 800
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   6a00                 | push                0
            //   6a01                 | push                1

        $sequence_8 = { c60100 5f 5e 33c0 }
            // n = 4, score = 700
            //   c60100               | mov                 byte ptr [ecx], 0
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   33c0                 | xor                 eax, eax

        $sequence_9 = { 6a00 52 c744242401000000 8944242c c744243002000000 ff15???????? }
            // n = 6, score = 700
            //   6a00                 | push                0
            //   52                   | push                edx
            //   c744242401000000     | mov                 dword ptr [esp + 0x24], 1
            //   8944242c             | mov                 dword ptr [esp + 0x2c], eax
            //   c744243002000000     | mov                 dword ptr [esp + 0x30], 2
            //   ff15????????         |                     

        $sequence_10 = { 8d8530fcffff 50 e8???????? 83c40c }
            // n = 4, score = 700
            //   8d8530fcffff         | lea                 eax, dword ptr [ebp - 0x3d0]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_11 = { 83c40c eb02 33c0 8b4df4 }
            // n = 4, score = 700
            //   83c40c               | add                 esp, 0xc
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_12 = { 7509 80780120 7503 83c002 }
            // n = 4, score = 700
            //   7509                 | jne                 0xb
            //   80780120             | cmp                 byte ptr [eax + 1], 0x20
            //   7503                 | jne                 5
            //   83c002               | add                 eax, 2

        $sequence_13 = { e8???????? 50 6804010000 68???????? }
            // n = 4, score = 600
            //   e8????????           |                     
            //   50                   | push                eax
            //   6804010000           | push                0x104
            //   68????????           |                     

        $sequence_14 = { e8???????? 83c408 6800010000 68???????? }
            // n = 4, score = 600
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   6800010000           | push                0x100
            //   68????????           |                     

        $sequence_15 = { c1f802 c0e204 0ac2 8b542410 884500 }
            // n = 5, score = 500
            //   c1f802               | sar                 eax, 2
            //   c0e204               | shl                 dl, 4
            //   0ac2                 | or                  al, dl
            //   8b542410             | mov                 edx, dword ptr [esp + 0x10]
            //   884500               | mov                 byte ptr [ebp], al

        $sequence_16 = { 833800 750f c705????????01000000 e9???????? }
            // n = 4, score = 500
            //   833800               | cmp                 dword ptr [eax], 0
            //   750f                 | jne                 0x11
            //   c705????????01000000     |     
            //   e9????????           |                     

        $sequence_17 = { e9???????? 8b4c2428 8b542410 5f c6450000 }
            // n = 5, score = 500
            //   e9????????           |                     
            //   8b4c2428             | mov                 ecx, dword ptr [esp + 0x28]
            //   8b542410             | mov                 edx, dword ptr [esp + 0x10]
            //   5f                   | pop                 edi
            //   c6450000             | mov                 byte ptr [ebp], 0

        $sequence_18 = { c1e302 85c0 7402 8918 }
            // n = 4, score = 500
            //   c1e302               | shl                 ebx, 2
            //   85c0                 | test                eax, eax
            //   7402                 | je                  4
            //   8918                 | mov                 dword ptr [eax], ebx

        $sequence_19 = { c644243423 c644243572 c64424367a c644243700 }
            // n = 4, score = 300
            //   c644243423           | mov                 byte ptr [esp + 0x34], 0x23
            //   c644243572           | mov                 byte ptr [esp + 0x35], 0x72
            //   c64424367a           | mov                 byte ptr [esp + 0x36], 0x7a
            //   c644243700           | mov                 byte ptr [esp + 0x37], 0

        $sequence_20 = { d2cc bbe3b46b7e 6aa2 dd45ff }
            // n = 4, score = 200
            //   d2cc                 | ror                 ah, cl
            //   bbe3b46b7e           | mov                 ebx, 0x7e6bb4e3
            //   6aa2                 | push                -0x5e
            //   dd45ff               | fld                 qword ptr [ebp - 1]

        $sequence_21 = { de6c58ae c8201cdd f7be5b408d58 1b7f01 d2cc }
            // n = 5, score = 200
            //   de6c58ae             | fisubr              word ptr [eax + ebx*2 - 0x52]
            //   c8201cdd             | enter               0x1c20, -0x23
            //   f7be5b408d58         | idiv                dword ptr [esi + 0x588d405b]
            //   1b7f01               | sbb                 edi, dword ptr [edi + 1]
            //   d2cc                 | ror                 ah, cl

        $sequence_22 = { e9???????? 4885c9 0f84175cffff 488b4108 }
            // n = 4, score = 100
            //   e9????????           |                     
            //   4885c9               | mov                 dword ptr [esp + 0x10], ebx
            //   0f84175cffff         | dec                 eax
            //   488b4108             | test                ecx, ecx

        $sequence_23 = { e9???????? 4885c9 0f840c020000 48895c2410 }
            // n = 4, score = 100
            //   e9????????           |                     
            //   4885c9               | dec                 eax
            //   0f840c020000         | mov                 dword ptr [esp + 8], ebx
            //   48895c2410           | push                edi

        $sequence_24 = { e9???????? 4885c9 0f8402010000 48895c2408 }
            // n = 4, score = 100
            //   e9????????           |                     
            //   4885c9               | mov                 esi, eax
            //   0f8402010000         | dec                 eax
            //   48895c2408           | and                 eax, eax

        $sequence_25 = { e9???????? 4883ec38 8b05???????? 448b0d???????? 4c4889c6 4821c0 750a }
            // n = 7, score = 100
            //   e9????????           |                     
            //   4883ec38             | dec                 eax
            //   8b05????????         |                     
            //   448b0d????????       |                     
            //   4c4889c6             | sub                 esp, 0x38
            //   4821c0               | dec                 esp
            //   750a                 | dec                 eax

    condition:
        7 of them and filesize < 2957312
}