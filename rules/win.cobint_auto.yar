rule win_cobint_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.cobint."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobint"
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
        $sequence_0 = { 59 8b4dec 890b 8b4508 8945e8 }
            // n = 5, score = 400
            //   59                   | pop                 ecx
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   890b                 | mov                 dword ptr [ebx], ecx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax

        $sequence_1 = { 8b35???????? ffd6 f7d8 c745f404000000 1bc0 }
            // n = 5, score = 400
            //   8b35????????         |                     
            //   ffd6                 | call                esi
            //   f7d8                 | neg                 eax
            //   c745f404000000       | mov                 dword ptr [ebp - 0xc], 4
            //   1bc0                 | sbb                 eax, eax

        $sequence_2 = { 33f6 a1???????? 03c6 3938 }
            // n = 4, score = 400
            //   33f6                 | xor                 esi, esi
            //   a1????????           |                     
            //   03c6                 | add                 eax, esi
            //   3938                 | cmp                 dword ptr [eax], edi

        $sequence_3 = { 50 a3???????? e8???????? 8325????????00 57 e8???????? }
            // n = 6, score = 400
            //   50                   | push                eax
            //   a3????????           |                     
            //   e8????????           |                     
            //   8325????????00       |                     
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_4 = { 57 ff75f0 ff15???????? 85c0 7447 }
            // n = 5, score = 400
            //   57                   | push                edi
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7447                 | je                  0x49

        $sequence_5 = { 8b0d???????? 33d2 53 8b5d08 8bc1 }
            // n = 5, score = 400
            //   8b0d????????         |                     
            //   33d2                 | xor                 edx, edx
            //   53                   | push                ebx
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   8bc1                 | mov                 eax, ecx

        $sequence_6 = { 56 51 50 68???????? eb11 c605????????01 }
            // n = 6, score = 400
            //   56                   | push                esi
            //   51                   | push                ecx
            //   50                   | push                eax
            //   68????????           |                     
            //   eb11                 | jmp                 0x13
            //   c605????????01       |                     

        $sequence_7 = { 7412 83ea01 7530 56 51 }
            // n = 5, score = 400
            //   7412                 | je                  0x14
            //   83ea01               | sub                 edx, 1
            //   7530                 | jne                 0x32
            //   56                   | push                esi
            //   51                   | push                ecx

        $sequence_8 = { 8a45ec 8802 eb0b 8b4d08 034df0 8a55ed 8811 }
            // n = 7, score = 200
            //   8a45ec               | mov                 al, byte ptr [ebp - 0x14]
            //   8802                 | mov                 byte ptr [edx], al
            //   eb0b                 | jmp                 0xd
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   034df0               | add                 ecx, dword ptr [ebp - 0x10]
            //   8a55ed               | mov                 dl, byte ptr [ebp - 0x13]
            //   8811                 | mov                 byte ptr [ecx], dl

        $sequence_9 = { 58 83c005 c3 31b7807c30ae 807c909090 90 bdfd807c90 }
            // n = 7, score = 200
            //   58                   | pop                 eax
            //   83c005               | add                 eax, 5
            //   c3                   | ret                 
            //   31b7807c30ae         | xor                 dword ptr [edi - 0x51cf8380], esi
            //   807c909090           | cmp                 byte ptr [eax + edx*4 - 0x70], 0x90
            //   90                   | nop                 
            //   bdfd807c90           | mov                 ebp, 0x907c80fd

        $sequence_10 = { 837d1000 740d 8b5508 0355f0 8a45ec }
            // n = 5, score = 200
            //   837d1000             | cmp                 dword ptr [ebp + 0x10], 0
            //   740d                 | je                  0xf
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   0355f0               | add                 edx, dword ptr [ebp - 0x10]
            //   8a45ec               | mov                 al, byte ptr [ebp - 0x14]

        $sequence_11 = { e10b 96 7c90 90 90 }
            // n = 5, score = 200
            //   e10b                 | loope               0xd
            //   96                   | xchg                eax, esi
            //   7c90                 | jl                  0xffffff92
            //   90                   | nop                 
            //   90                   | nop                 

        $sequence_12 = { 7418 037dec 8d45ec 50 b800a80000 2bc7 50 }
            // n = 7, score = 200
            //   7418                 | je                  0x1a
            //   037dec               | add                 edi, dword ptr [ebp - 0x14]
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   50                   | push                eax
            //   b800a80000           | mov                 eax, 0xa800
            //   2bc7                 | sub                 eax, edi
            //   50                   | push                eax

        $sequence_13 = { bab1c50790 8bf0 33ff e8???????? }
            // n = 4, score = 200
            //   bab1c50790           | mov                 edx, 0x9007c5b1
            //   8bf0                 | mov                 esi, eax
            //   33ff                 | xor                 edi, edi
            //   e8????????           |                     

        $sequence_14 = { 1a807c170e81 7cd7 9b 807c909090 90 90 90 }
            // n = 7, score = 200
            //   1a807c170e81         | sbb                 al, byte ptr [eax - 0x7ef1e884]
            //   7cd7                 | jl                  0xffffffd9
            //   9b                   | wait                
            //   807c909090           | cmp                 byte ptr [eax + edx*4 - 0x70], 0x90
            //   90                   | nop                 
            //   90                   | nop                 
            //   90                   | nop                 

        $sequence_15 = { 90 749b 807ce19a80 7c90 90 }
            // n = 5, score = 200
            //   90                   | nop                 
            //   749b                 | je                  0xffffff9d
            //   807ce19a80           | cmp                 byte ptr [ecx - 0x66], 0x80
            //   7c90                 | jl                  0xffffff92
            //   90                   | nop                 

        $sequence_16 = { 8945bc 51 6800008000 51 51 51 8d8524feffff }
            // n = 7, score = 200
            //   8945bc               | mov                 dword ptr [ebp - 0x44], eax
            //   51                   | push                ecx
            //   6800008000           | push                0x800000
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   8d8524feffff         | lea                 eax, [ebp - 0x1dc]

        $sequence_17 = { 8be5 5d c3 8b4324 8d0450 }
            // n = 5, score = 200
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b4324               | mov                 eax, dword ptr [ebx + 0x24]
            //   8d0450               | lea                 eax, [eax + edx*2]

        $sequence_18 = { bdfd807c90 90 90 90 90 90 }
            // n = 6, score = 200
            //   bdfd807c90           | mov                 ebp, 0x907c80fd
            //   90                   | nop                 
            //   90                   | nop                 
            //   90                   | nop                 
            //   90                   | nop                 
            //   90                   | nop                 

        $sequence_19 = { 8d9524feffff 8bcb 897db8 e8???????? 8bf0 8d8524feffff }
            // n = 6, score = 200
            //   8d9524feffff         | lea                 edx, [ebp - 0x1dc]
            //   8bcb                 | mov                 ecx, ebx
            //   897db8               | mov                 dword ptr [ebp - 0x48], edi
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   8d8524feffff         | lea                 eax, [ebp - 0x1dc]

        $sequence_20 = { 8945f8 51 6800a80000 56 53 ffd0 eb1a }
            // n = 7, score = 200
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   51                   | push                ecx
            //   6800a80000           | push                0xa800
            //   56                   | push                esi
            //   53                   | push                ebx
            //   ffd0                 | call                eax
            //   eb1a                 | jmp                 0x1c

        $sequence_21 = { 8d8524feffff 50 ffd7 8bf8 c745f405000000 32db }
            // n = 6, score = 200
            //   8d8524feffff         | lea                 eax, [ebp - 0x1dc]
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   8bf8                 | mov                 edi, eax
            //   c745f405000000       | mov                 dword ptr [ebp - 0xc], 5
            //   32db                 | xor                 bl, bl

        $sequence_22 = { 33c0 8b12 85d2 75c4 }
            // n = 4, score = 200
            //   33c0                 | xor                 eax, eax
            //   8b12                 | mov                 edx, dword ptr [edx]
            //   85d2                 | test                edx, edx
            //   75c4                 | jne                 0xffffffc6

        $sequence_23 = { 90 90 bffc807c28 1a807c170e81 7cd7 }
            // n = 5, score = 200
            //   90                   | nop                 
            //   90                   | nop                 
            //   bffc807c28           | mov                 edi, 0x287c80fc
            //   1a807c170e81         | sbb                 al, byte ptr [eax - 0x7ef1e884]
            //   7cd7                 | jl                  0xffffffd9

    condition:
        7 of them and filesize < 65536
}