rule win_redsalt_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.redsalt."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redsalt"
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
        $sequence_0 = { 750b 68e8030000 ff15???????? e8???????? 85c0 }
            // n = 5, score = 1100
            //   750b                 | jne                 0xd
            //   68e8030000           | push                0x3e8
            //   ff15????????         |                     
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_1 = { 83c414 33c9 83f8ff 0f95c1 }
            // n = 4, score = 1100
            //   83c414               | add                 esp, 0x14
            //   33c9                 | xor                 ecx, ecx
            //   83f8ff               | cmp                 eax, -1
            //   0f95c1               | setne               cl

        $sequence_2 = { 7515 c705????????01000000 ff15???????? e9???????? }
            // n = 4, score = 1000
            //   7515                 | jne                 0x17
            //   c705????????01000000     |     
            //   ff15????????         |                     
            //   e9????????           |                     

        $sequence_3 = { c745d060ea0000 6a04 8d45d0 50 6806100000 }
            // n = 5, score = 900
            //   c745d060ea0000       | mov                 dword ptr [ebp - 0x30], 0xea60
            //   6a04                 | push                4
            //   8d45d0               | lea                 eax, [ebp - 0x30]
            //   50                   | push                eax
            //   6806100000           | push                0x1006

        $sequence_4 = { 85c0 7413 e8???????? 85c0 750a 6a32 }
            // n = 6, score = 900
            //   85c0                 | test                eax, eax
            //   7413                 | je                  0x15
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   750a                 | jne                 0xc
            //   6a32                 | push                0x32

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

        $sequence_8 = { 6a00 52 c744242401000000 8944242c c744243002000000 }
            // n = 5, score = 700
            //   6a00                 | push                0
            //   52                   | push                edx
            //   c744242401000000     | mov                 dword ptr [esp + 0x24], 1
            //   8944242c             | mov                 dword ptr [esp + 0x2c], eax
            //   c744243002000000     | mov                 dword ptr [esp + 0x30], 2

        $sequence_9 = { c60100 5f 5e 33c0 }
            // n = 4, score = 700
            //   c60100               | mov                 byte ptr [ecx], 0
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   33c0                 | xor                 eax, eax

        $sequence_10 = { 68ff7f0000 8d85e07fffff 50 e8???????? }
            // n = 4, score = 700
            //   68ff7f0000           | push                0x7fff
            //   8d85e07fffff         | lea                 eax, [ebp - 0x8020]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_11 = { 7509 80780120 7503 83c002 }
            // n = 4, score = 700
            //   7509                 | jne                 0xb
            //   80780120             | cmp                 byte ptr [eax + 1], 0x20
            //   7503                 | jne                 5
            //   83c002               | add                 eax, 2

        $sequence_12 = { 8d8530fcffff 50 e8???????? 83c40c }
            // n = 4, score = 700
            //   8d8530fcffff         | lea                 eax, [ebp - 0x3d0]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_13 = { e8???????? 83c408 6800010000 68???????? }
            // n = 4, score = 600
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   6800010000           | push                0x100
            //   68????????           |                     

        $sequence_14 = { 750a b857000000 e9???????? 833d????????00 }
            // n = 4, score = 500
            //   750a                 | jne                 0xc
            //   b857000000           | mov                 eax, 0x57
            //   e9????????           |                     
            //   833d????????00       |                     

        $sequence_15 = { c0e106 0aca 884d00 45 40 89442410 }
            // n = 6, score = 500
            //   c0e106               | shl                 cl, 6
            //   0aca                 | or                  cl, dl
            //   884d00               | mov                 byte ptr [ebp], cl
            //   45                   | inc                 ebp
            //   40                   | inc                 eax
            //   89442410             | mov                 dword ptr [esp + 0x10], eax

        $sequence_16 = { d1ed 33c0 83ef03 8a06 83c603 c1e802 41 }
            // n = 7, score = 500
            //   d1ed                 | shr                 ebp, 1
            //   33c0                 | xor                 eax, eax
            //   83ef03               | sub                 edi, 3
            //   8a06                 | mov                 al, byte ptr [esi]
            //   83c603               | add                 esi, 3
            //   c1e802               | shr                 eax, 2
            //   41                   | inc                 ecx

        $sequence_17 = { 833800 750f c705????????01000000 e9???????? }
            // n = 4, score = 500
            //   833800               | cmp                 dword ptr [eax], 0
            //   750f                 | jne                 0x11
            //   c705????????01000000     |     
            //   e9????????           |                     

        $sequence_18 = { eb03 83cfff 8bc7 c1f802 c0e204 0ac2 8b542410 }
            // n = 7, score = 500
            //   eb03                 | jmp                 5
            //   83cfff               | or                  edi, 0xffffffff
            //   8bc7                 | mov                 eax, edi
            //   c1f802               | sar                 eax, 2
            //   c0e204               | shl                 dl, 4
            //   0ac2                 | or                  al, dl
            //   8b542410             | mov                 edx, dword ptr [esp + 0x10]

        $sequence_19 = { c705????????00090000 eb0a c705????????00080000 eb0a c705????????00070000 }
            // n = 5, score = 500
            //   c705????????00090000     |     
            //   eb0a                 | jmp                 0xc
            //   c705????????00080000     |     
            //   eb0a                 | jmp                 0xc
            //   c705????????00070000     |     

        $sequence_20 = { c644243423 c644243572 c64424367a c644243700 }
            // n = 4, score = 300
            //   c644243423           | mov                 byte ptr [esp + 0x34], 0x23
            //   c644243572           | mov                 byte ptr [esp + 0x35], 0x72
            //   c64424367a           | mov                 byte ptr [esp + 0x36], 0x7a
            //   c644243700           | mov                 byte ptr [esp + 0x37], 0

        $sequence_21 = { 66890451 8b442420 83c001 89442420 }
            // n = 4, score = 100
            //   66890451             | mov                 eax, dword ptr [esp + 0x20]
            //   8b442420             | mov                 word ptr [ecx + edx*2], ax
            //   83c001               | mov                 eax, dword ptr [esp + 0x20]
            //   89442420             | add                 eax, 1

        $sequence_22 = { 668907 4821f6 0f84e7010000 c70601000000 }
            // n = 4, score = 100
            //   668907               | mov                 dword ptr [esp + 0x28], eax
            //   4821f6               | mov                 word ptr [edi], ax
            //   0f84e7010000         | dec                 eax
            //   c70601000000         | and                 esi, esi

        $sequence_23 = { 66890451 8b442408 83c001 89442408 eb8a }
            // n = 5, score = 100
            //   66890451             | mov                 word ptr [ecx + edx*2], ax
            //   8b442408             | mov                 eax, dword ptr [esp + 8]
            //   83c001               | add                 eax, 1
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   eb8a                 | jmp                 0xffffff8c

    condition:
        7 of them and filesize < 2957312
}