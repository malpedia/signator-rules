rule win_hzrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.hzrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hzrat"
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
        $sequence_0 = { 3b0d???????? 731c 8bc1 83e13f c1e806 6bc938 8b048510fa4200 }
            // n = 7, score = 100
            //   3b0d????????         |                     
            //   731c                 | jae                 0x1e
            //   8bc1                 | mov                 eax, ecx
            //   83e13f               | and                 ecx, 0x3f
            //   c1e806               | shr                 eax, 6
            //   6bc938               | imul                ecx, ecx, 0x38
            //   8b048510fa4200       | mov                 eax, dword ptr [eax*4 + 0x42fa10]

        $sequence_1 = { e8???????? 3b580c 730d 0faee8 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   3b580c               | cmp                 ebx, dword ptr [eax + 0xc]
            //   730d                 | jae                 0xf
            //   0faee8               | lfence              

        $sequence_2 = { 0f8c8f030000 3b4f04 0f8d86030000 8b5d08 813b63736de0 }
            // n = 5, score = 100
            //   0f8c8f030000         | jl                  0x395
            //   3b4f04               | cmp                 ecx, dword ptr [edi + 4]
            //   0f8d86030000         | jge                 0x38c
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   813b63736de0         | cmp                 dword ptr [ebx], 0xe06d7363

        $sequence_3 = { 7461 8b4104 8b8880f04200 8a8088f04200 8845ef 8b4120 833800 }
            // n = 7, score = 100
            //   7461                 | je                  0x63
            //   8b4104               | mov                 eax, dword ptr [ecx + 4]
            //   8b8880f04200         | mov                 ecx, dword ptr [eax + 0x42f080]
            //   8a8088f04200         | mov                 al, byte ptr [eax + 0x42f088]
            //   8845ef               | mov                 byte ptr [ebp - 0x11], al
            //   8b4120               | mov                 eax, dword ptr [ecx + 0x20]
            //   833800               | cmp                 dword ptr [eax], 0

        $sequence_4 = { 7717 e8???????? 8bdc 85db 0f8424010000 c703cccc0000 eb17 }
            // n = 7, score = 100
            //   7717                 | ja                  0x19
            //   e8????????           |                     
            //   8bdc                 | mov                 ebx, esp
            //   85db                 | test                ebx, ebx
            //   0f8424010000         | je                  0x12a
            //   c703cccc0000         | mov                 dword ptr [ebx], 0xcccc
            //   eb17                 | jmp                 0x19

        $sequence_5 = { 3bcf 7d09 80343142 41 3bcf 7cf7 6a00 }
            // n = 7, score = 100
            //   3bcf                 | cmp                 ecx, edi
            //   7d09                 | jge                 0xb
            //   80343142             | xor                 byte ptr [ecx + esi], 0x42
            //   41                   | inc                 ecx
            //   3bcf                 | cmp                 ecx, edi
            //   7cf7                 | jl                  0xfffffff9
            //   6a00                 | push                0

        $sequence_6 = { c1eb06 6bf838 8b049d10fa4200 f644072801 7444 837c0718ff 743d }
            // n = 7, score = 100
            //   c1eb06               | shr                 ebx, 6
            //   6bf838               | imul                edi, eax, 0x38
            //   8b049d10fa4200       | mov                 eax, dword ptr [ebx*4 + 0x42fa10]
            //   f644072801           | test                byte ptr [edi + eax + 0x28], 1
            //   7444                 | je                  0x46
            //   837c0718ff           | cmp                 dword ptr [edi + eax + 0x18], -1
            //   743d                 | je                  0x3f

        $sequence_7 = { 8bf1 89b58cfeffff 33c0 8d8de0feffff 898564feffff 8985dcfeffff }
            // n = 6, score = 100
            //   8bf1                 | mov                 esi, ecx
            //   89b58cfeffff         | mov                 dword ptr [ebp - 0x174], esi
            //   33c0                 | xor                 eax, eax
            //   8d8de0feffff         | lea                 ecx, [ebp - 0x120]
            //   898564feffff         | mov                 dword ptr [ebp - 0x19c], eax
            //   8985dcfeffff         | mov                 dword ptr [ebp - 0x124], eax

        $sequence_8 = { c3 e8???????? 90 57 394000 6b3d????????40 005342 }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   e8????????           |                     
            //   90                   | nop                 
            //   57                   | push                edi
            //   394000               | cmp                 dword ptr [eax], eax
            //   6b3d????????40       |                     
            //   005342               | add                 byte ptr [ebx + 0x42], dl

        $sequence_9 = { eb4d 0faee8 ff771c 53 e8???????? 59 59 }
            // n = 7, score = 100
            //   eb4d                 | jmp                 0x4f
            //   0faee8               | lfence              
            //   ff771c               | push                dword ptr [edi + 0x1c]
            //   53                   | push                ebx
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx

    condition:
        7 of them and filesize < 409600
}