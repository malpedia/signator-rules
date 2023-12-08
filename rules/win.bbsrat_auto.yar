rule win_bbsrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.bbsrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bbsrat"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
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
        $sequence_0 = { e8???????? 8b7c2410 81c610020000 d1eb 45 85db 75b5 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b7c2410             | mov                 edi, dword ptr [esp + 0x10]
            //   81c610020000         | add                 esi, 0x210
            //   d1eb                 | shr                 ebx, 1
            //   45                   | inc                 ebp
            //   85db                 | test                ebx, ebx
            //   75b5                 | jne                 0xffffffb7

        $sequence_1 = { 83c8ff 898e44020000 899648020000 57 894308 894304 8903 }
            // n = 7, score = 100
            //   83c8ff               | or                  eax, 0xffffffff
            //   898e44020000         | mov                 dword ptr [esi + 0x244], ecx
            //   899648020000         | mov                 dword ptr [esi + 0x248], edx
            //   57                   | push                edi
            //   894308               | mov                 dword ptr [ebx + 8], eax
            //   894304               | mov                 dword ptr [ebx + 4], eax
            //   8903                 | mov                 dword ptr [ebx], eax

        $sequence_2 = { 03c0 03c0 50 898374010000 e8???????? 8b8b74010000 83c404 }
            // n = 7, score = 100
            //   03c0                 | add                 eax, eax
            //   03c0                 | add                 eax, eax
            //   50                   | push                eax
            //   898374010000         | mov                 dword ptr [ebx + 0x174], eax
            //   e8????????           |                     
            //   8b8b74010000         | mov                 ecx, dword ptr [ebx + 0x174]
            //   83c404               | add                 esp, 4

        $sequence_3 = { 8be5 5d c20c00 51 e8???????? 5e 5b }
            // n = 7, score = 100
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20c00               | ret                 0xc
            //   51                   | push                ecx
            //   e8????????           |                     
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_4 = { ffd7 895e24 8b461c 3bc3 741a 53 50 }
            // n = 7, score = 100
            //   ffd7                 | call                edi
            //   895e24               | mov                 dword ptr [esi + 0x24], ebx
            //   8b461c               | mov                 eax, dword ptr [esi + 0x1c]
            //   3bc3                 | cmp                 eax, ebx
            //   741a                 | je                  0x1c
            //   53                   | push                ebx
            //   50                   | push                eax

        $sequence_5 = { eb21 83f805 7529 8d8c243c010000 51 8d842448030000 e8???????? }
            // n = 7, score = 100
            //   eb21                 | jmp                 0x23
            //   83f805               | cmp                 eax, 5
            //   7529                 | jne                 0x2b
            //   8d8c243c010000       | lea                 ecx, [esp + 0x13c]
            //   51                   | push                ecx
            //   8d842448030000       | lea                 eax, [esp + 0x348]
            //   e8????????           |                     

        $sequence_6 = { ff15???????? 8bf8 6a10 56 6861001100 }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   6a10                 | push                0x10
            //   56                   | push                esi
            //   6861001100           | push                0x110061

        $sequence_7 = { 52 8d6e18 55 8d7e0c 57 894608 e8???????? }
            // n = 7, score = 100
            //   52                   | push                edx
            //   8d6e18               | lea                 ebp, [esi + 0x18]
            //   55                   | push                ebp
            //   8d7e0c               | lea                 edi, [esi + 0xc]
            //   57                   | push                edi
            //   894608               | mov                 dword ptr [esi + 8], eax
            //   e8????????           |                     

        $sequence_8 = { ffd7 a3???????? 85c0 7412 8d4c2408 51 }
            // n = 6, score = 100
            //   ffd7                 | call                edi
            //   a3????????           |                     
            //   85c0                 | test                eax, eax
            //   7412                 | je                  0x14
            //   8d4c2408             | lea                 ecx, [esp + 8]
            //   51                   | push                ecx

        $sequence_9 = { 6a00 52 8bd8 56 895c2428 ff15???????? 8b4f0c }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   52                   | push                edx
            //   8bd8                 | mov                 ebx, eax
            //   56                   | push                esi
            //   895c2428             | mov                 dword ptr [esp + 0x28], ebx
            //   ff15????????         |                     
            //   8b4f0c               | mov                 ecx, dword ptr [edi + 0xc]

    condition:
        7 of them and filesize < 434176
}