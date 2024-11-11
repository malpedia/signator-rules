rule win_quiterat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.quiterat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.quiterat"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
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
        $sequence_0 = { ff31 8bcb ff5018 e9???????? 8b03 8bcb 8b4014 }
            // n = 7, score = 100
            //   ff31                 | push                dword ptr [ecx]
            //   8bcb                 | mov                 ecx, ebx
            //   ff5018               | call                dword ptr [eax + 0x18]
            //   e9????????           |                     
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   8bcb                 | mov                 ecx, ebx
            //   8b4014               | mov                 eax, dword ptr [eax + 0x14]

        $sequence_1 = { eb31 80bef800000000 7426 8b4c2418 e8???????? 8b4c2418 6830750000 }
            // n = 7, score = 100
            //   eb31                 | jmp                 0x33
            //   80bef800000000       | cmp                 byte ptr [esi + 0xf8], 0
            //   7426                 | je                  0x28
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]
            //   e8????????           |                     
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]
            //   6830750000           | push                0x7530

        $sequence_2 = { b803000000 8d4e60 89442410 8d442434 50 8d442420 50 }
            // n = 7, score = 100
            //   b803000000           | mov                 eax, 3
            //   8d4e60               | lea                 ecx, [esi + 0x60]
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   8d442434             | lea                 eax, [esp + 0x34]
            //   50                   | push                eax
            //   8d442420             | lea                 eax, [esp + 0x20]
            //   50                   | push                eax

        $sequence_3 = { f00fc11e 4b 0f95c0 84c0 0f858a030000 6a04 6a02 }
            // n = 7, score = 100
            //   f00fc11e             | lock xadd           dword ptr [esi], ebx
            //   4b                   | dec                 ebx
            //   0f95c0               | setne               al
            //   84c0                 | test                al, al
            //   0f858a030000         | jne                 0x390
            //   6a04                 | push                4
            //   6a02                 | push                2

        $sequence_4 = { c644241c01 eb05 c644241c00 f6c308 740c 8d4c2414 83e3f7 }
            // n = 7, score = 100
            //   c644241c01           | mov                 byte ptr [esp + 0x1c], 1
            //   eb05                 | jmp                 7
            //   c644241c00           | mov                 byte ptr [esp + 0x1c], 0
            //   f6c308               | test                bl, 8
            //   740c                 | je                  0xe
            //   8d4c2414             | lea                 ecx, [esp + 0x14]
            //   83e3f7               | and                 ebx, 0xfffffff7

        $sequence_5 = { f7f6 2b4c2418 3bc8 0f87e0000000 0fafce 03f9 33f6 }
            // n = 7, score = 100
            //   f7f6                 | div                 esi
            //   2b4c2418             | sub                 ecx, dword ptr [esp + 0x18]
            //   3bc8                 | cmp                 ecx, eax
            //   0f87e0000000         | ja                  0xe6
            //   0fafce               | imul                ecx, esi
            //   03f9                 | add                 edi, ecx
            //   33f6                 | xor                 esi, esi

        $sequence_6 = { e8???????? 8d4c2410 e8???????? 8b442440 8b4c2430 64890d00000000 59 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8d4c2410             | lea                 ecx, [esp + 0x10]
            //   e8????????           |                     
            //   8b442440             | mov                 eax, dword ptr [esp + 0x40]
            //   8b4c2430             | mov                 ecx, dword ptr [esp + 0x30]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   59                   | pop                 ecx

        $sequence_7 = { c7460400000000 85ed 7e1c 90 8b4604 8b4e08 03c0 }
            // n = 7, score = 100
            //   c7460400000000       | mov                 dword ptr [esi + 4], 0
            //   85ed                 | test                ebp, ebp
            //   7e1c                 | jle                 0x1e
            //   90                   | nop                 
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]
            //   03c0                 | add                 eax, eax

        $sequence_8 = { e9???????? 8b06 83780400 7558 8d442434 50 e8???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   83780400             | cmp                 dword ptr [eax + 4], 0
            //   7558                 | jne                 0x5a
            //   8d442434             | lea                 eax, [esp + 0x34]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_9 = { 8b06 85c0 7415 83f8ff 7435 8bc7 f00fc106 }
            // n = 7, score = 100
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   85c0                 | test                eax, eax
            //   7415                 | je                  0x17
            //   83f8ff               | cmp                 eax, -1
            //   7435                 | je                  0x37
            //   8bc7                 | mov                 eax, edi
            //   f00fc106             | lock xadd           dword ptr [esi], eax

    condition:
        7 of them and filesize < 5892096
}