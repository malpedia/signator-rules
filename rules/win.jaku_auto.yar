rule win_jaku_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.jaku."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.jaku"
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
        $sequence_0 = { 83c410 8945c8 f6430c20 0f8467ffffff }
            // n = 4, score = 1500
            //   83c410               | add                 esp, 0x10
            //   8945c8               | mov                 dword ptr [ebp - 0x38], eax
            //   f6430c20             | test                byte ptr [ebx + 0xc], 0x20
            //   0f8467ffffff         | je                  0xffffff6d

        $sequence_1 = { 8b45d8 83c708 ebcd 84c0 0f848b000000 a8f0 0f8583000000 }
            // n = 7, score = 1500
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]
            //   83c708               | add                 edi, 8
            //   ebcd                 | jmp                 0xffffffcf
            //   84c0                 | test                al, al
            //   0f848b000000         | je                  0x91
            //   a8f0                 | test                al, 0xf0
            //   0f8583000000         | jne                 0x89

        $sequence_2 = { 8ac8 034df4 6a01 8945d8 58 }
            // n = 5, score = 1500
            //   8ac8                 | mov                 cl, al
            //   034df4               | add                 ecx, dword ptr [ebp - 0xc]
            //   6a01                 | push                1
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   58                   | pop                 eax

        $sequence_3 = { 740d 56 57 50 e8???????? }
            // n = 5, score = 1500
            //   740d                 | je                  0xf
            //   56                   | push                esi
            //   57                   | push                edi
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_4 = { 2bf8 d3e2 4a 23d3 015644 d3eb 0186c41b0000 }
            // n = 7, score = 1500
            //   2bf8                 | sub                 edi, eax
            //   d3e2                 | shl                 edx, cl
            //   4a                   | dec                 edx
            //   23d3                 | and                 edx, ebx
            //   015644               | add                 dword ptr [esi + 0x44], edx
            //   d3eb                 | shr                 ebx, cl
            //   0186c41b0000         | add                 dword ptr [esi + 0x1bc4], eax

        $sequence_5 = { 83f913 7409 83f90e 7404 33c9 eb05 }
            // n = 6, score = 1500
            //   83f913               | cmp                 ecx, 0x13
            //   7409                 | je                  0xb
            //   83f90e               | cmp                 ecx, 0xe
            //   7404                 | je                  6
            //   33c9                 | xor                 ecx, ecx
            //   eb05                 | jmp                 7

        $sequence_6 = { 8975ec ff7508 e8???????? 59 3bc6 59 }
            // n = 6, score = 1500
            //   8975ec               | mov                 dword ptr [ebp - 0x14], esi
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   3bc6                 | cmp                 eax, esi
            //   59                   | pop                 ecx

        $sequence_7 = { 03c8 51 e8???????? 83c40c f6461102 7414 ff75f0 }
            // n = 7, score = 1500
            //   03c8                 | add                 ecx, eax
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   f6461102             | test                byte ptr [esi + 0x11], 2
            //   7414                 | je                  0x16
            //   ff75f0               | push                dword ptr [ebp - 0x10]

        $sequence_8 = { 68???????? ff15???????? c3 b8???????? e8???????? 83ec2c }
            // n = 6, score = 700
            //   68????????           |                     
            //   ff15????????         |                     
            //   c3                   | ret                 
            //   b8????????           |                     
            //   e8????????           |                     
            //   83ec2c               | sub                 esp, 0x2c

        $sequence_9 = { 6a01 03c3 68???????? 50 e8???????? 83c40c }
            // n = 6, score = 500
            //   6a01                 | push                1
            //   03c3                 | add                 eax, ebx
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_10 = { ff742408 e8???????? c20800 8bc1 }
            // n = 4, score = 500
            //   ff742408             | push                dword ptr [esp + 8]
            //   e8????????           |                     
            //   c20800               | ret                 8
            //   8bc1                 | mov                 eax, ecx

        $sequence_11 = { 7508 83c8ff e9???????? 8b839f830000 }
            // n = 4, score = 500
            //   7508                 | jne                 0xa
            //   83c8ff               | or                  eax, 0xffffffff
            //   e9????????           |                     
            //   8b839f830000         | mov                 eax, dword ptr [ebx + 0x839f]

        $sequence_12 = { 7507 b800308000 eb02 33c0 }
            // n = 4, score = 500
            //   7507                 | jne                 9
            //   b800308000           | mov                 eax, 0x803000
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax

        $sequence_13 = { 75dd 57 e8???????? 59 }
            // n = 4, score = 500
            //   75dd                 | jne                 0xffffffdf
            //   57                   | push                edi
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_14 = { 53 68000000a0 6a03 53 }
            // n = 4, score = 400
            //   53                   | push                ebx
            //   68000000a0           | push                0xa0000000
            //   6a03                 | push                3
            //   53                   | push                ebx

        $sequence_15 = { 5b c3 55 8bec 833d????????00 53 56 }
            // n = 7, score = 400
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   833d????????00       |                     
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_16 = { 56 e8???????? 59 8b4620 }
            // n = 4, score = 400
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8b4620               | mov                 eax, dword ptr [esi + 0x20]

        $sequence_17 = { 50 e8???????? 59 8b4e2c }
            // n = 4, score = 400
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8b4e2c               | mov                 ecx, dword ptr [esi + 0x2c]

        $sequence_18 = { e8???????? 59 eb57 53 }
            // n = 4, score = 400
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   eb57                 | jmp                 0x59
            //   53                   | push                ebx

        $sequence_19 = { 55 56 57 6880020000 }
            // n = 4, score = 400
            //   55                   | push                ebp
            //   56                   | push                esi
            //   57                   | push                edi
            //   6880020000           | push                0x280

        $sequence_20 = { 016c242c 8b44242c 5f 5e 5d }
            // n = 5, score = 300
            //   016c242c             | add                 dword ptr [esp + 0x2c], ebp
            //   8b44242c             | mov                 eax, dword ptr [esp + 0x2c]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp

        $sequence_21 = { 0245fd 3245fe 8a4dff d2c8 }
            // n = 4, score = 300
            //   0245fd               | add                 al, byte ptr [ebp - 3]
            //   3245fe               | xor                 al, byte ptr [ebp - 2]
            //   8a4dff               | mov                 cl, byte ptr [ebp - 1]
            //   d2c8                 | ror                 al, cl

        $sequence_22 = { 8b4de8 8b7df0 8bf0 33d2 f3a6 7459 8b4dec }
            // n = 7, score = 300
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   8b7df0               | mov                 edi, dword ptr [ebp - 0x10]
            //   8bf0                 | mov                 esi, eax
            //   33d2                 | xor                 edx, edx
            //   f3a6                 | repe cmpsb          byte ptr [esi], byte ptr es:[edi]
            //   7459                 | je                  0x5b
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]

        $sequence_23 = { 75f9 2bc2 3bf0 7328 6a01 }
            // n = 5, score = 300
            //   75f9                 | jne                 0xfffffffb
            //   2bc2                 | sub                 eax, edx
            //   3bf0                 | cmp                 esi, eax
            //   7328                 | jae                 0x2a
            //   6a01                 | push                1

        $sequence_24 = { 8d8d5cffffff 8bc4 8965e8 51 e8???????? }
            // n = 5, score = 300
            //   8d8d5cffffff         | lea                 ecx, dword ptr [ebp - 0xa4]
            //   8bc4                 | mov                 eax, esp
            //   8965e8               | mov                 dword ptr [ebp - 0x18], esp
            //   51                   | push                ecx
            //   e8????????           |                     

        $sequence_25 = { 8d4df0 e8???????? 68???????? 8d45f0 50 c745f0b0f14000 }
            // n = 6, score = 300
            //   8d4df0               | lea                 ecx, dword ptr [ebp - 0x10]
            //   e8????????           |                     
            //   68????????           |                     
            //   8d45f0               | lea                 eax, dword ptr [ebp - 0x10]
            //   50                   | push                eax
            //   c745f0b0f14000       | mov                 dword ptr [ebp - 0x10], 0x40f1b0

        $sequence_26 = { 85ff 741b 3bd0 7f74 7508 }
            // n = 5, score = 300
            //   85ff                 | test                edi, edi
            //   741b                 | je                  0x1d
            //   3bd0                 | cmp                 edx, eax
            //   7f74                 | jg                  0x76
            //   7508                 | jne                 0xa

        $sequence_27 = { 6a00 56 e8???????? 83c40c e8???????? 803d????????00 740a }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   e8????????           |                     
            //   803d????????00       |                     
            //   740a                 | je                  0xc

        $sequence_28 = { 59 ff431c 66c743104401 a1???????? 833d????????00 }
            // n = 5, score = 200
            //   59                   | pop                 ecx
            //   ff431c               | inc                 dword ptr [ebx + 0x1c]
            //   66c743104401         | mov                 word ptr [ebx + 0x10], 0x144
            //   a1????????           |                     
            //   833d????????00       |                     

    condition:
        7 of them and filesize < 2220032
}