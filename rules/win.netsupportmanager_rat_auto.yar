rule win_netsupportmanager_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.netsupportmanager_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.netsupportmanager_rat"
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
        $sequence_0 = { eb02 33c9 85c0 894e10 740f 8b4008 c7460401000000 }
            // n = 7, score = 100
            //   eb02                 | jmp                 4
            //   33c9                 | xor                 ecx, ecx
            //   85c0                 | test                eax, eax
            //   894e10               | mov                 dword ptr [esi + 0x10], ecx
            //   740f                 | je                  0x11
            //   8b4008               | mov                 eax, dword ptr [eax + 8]
            //   c7460401000000       | mov                 dword ptr [esi + 4], 1

        $sequence_1 = { 83c408 85c0 5e 7422 8b0d???????? 6a00 68???????? }
            // n = 7, score = 100
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   5e                   | pop                 esi
            //   7422                 | je                  0x24
            //   8b0d????????         |                     
            //   6a00                 | push                0
            //   68????????           |                     

        $sequence_2 = { ff15???????? 8b4330 c745fc00000000 8945ec 8b30 3bf0 7422 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8b4330               | mov                 eax, dword ptr [ebx + 0x30]
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8b30                 | mov                 esi, dword ptr [eax]
            //   3bf0                 | cmp                 esi, eax
            //   7422                 | je                  0x24

        $sequence_3 = { e8???????? 8b4340 83c404 46 83c704 3bf0 7cea }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b4340               | mov                 eax, dword ptr [ebx + 0x40]
            //   83c404               | add                 esp, 4
            //   46                   | inc                 esi
            //   83c704               | add                 edi, 4
            //   3bf0                 | cmp                 esi, eax
            //   7cea                 | jl                  0xffffffec

        $sequence_4 = { e9???????? 8d8d14fdffff e9???????? 8d8d40ddffff e9???????? 8d4de0 e9???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8d8d14fdffff         | lea                 ecx, [ebp - 0x2ec]
            //   e9????????           |                     
            //   8d8d40ddffff         | lea                 ecx, [ebp - 0x22c0]
            //   e9????????           |                     
            //   8d4de0               | lea                 ecx, [ebp - 0x20]
            //   e9????????           |                     

        $sequence_5 = { e9???????? 8b4510 8b4d0c 8b17 50 51 8bcf }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8b17                 | mov                 edx, dword ptr [edi]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   8bcf                 | mov                 ecx, edi

        $sequence_6 = { ff15???????? 8b565c 8b8290020000 85c0 7410 50 8b4608 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8b565c               | mov                 edx, dword ptr [esi + 0x5c]
            //   8b8290020000         | mov                 eax, dword ptr [edx + 0x290]
            //   85c0                 | test                eax, eax
            //   7410                 | je                  0x12
            //   50                   | push                eax
            //   8b4608               | mov                 eax, dword ptr [esi + 8]

        $sequence_7 = { ff5208 f7de 1bf6 23f7 83c604 56 ff15???????? }
            // n = 7, score = 100
            //   ff5208               | call                dword ptr [edx + 8]
            //   f7de                 | neg                 esi
            //   1bf6                 | sbb                 esi, esi
            //   23f7                 | and                 esi, edi
            //   83c604               | add                 esi, 4
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_8 = { e8???????? 8bce e8???????? 8b4628 3bc7 7409 50 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   8b4628               | mov                 eax, dword ptr [esi + 0x28]
            //   3bc7                 | cmp                 eax, edi
            //   7409                 | je                  0xb
            //   50                   | push                eax

        $sequence_9 = { e8???????? a1???????? 85c0 7511 8b0d???????? 6a00 6a04 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   a1????????           |                     
            //   85c0                 | test                eax, eax
            //   7511                 | jne                 0x13
            //   8b0d????????         |                     
            //   6a00                 | push                0
            //   6a04                 | push                4

    condition:
        7 of them and filesize < 4734976
}