rule win_furtim_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.furtim."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.furtim"
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
        $sequence_0 = { 33ff 50 57 57 897dfc ff9628040000 85c0 }
            // n = 7, score = 100
            //   33ff                 | xor                 edi, edi
            //   50                   | push                eax
            //   57                   | push                edi
            //   57                   | push                edi
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   ff9628040000         | call                dword ptr [esi + 0x428]
            //   85c0                 | test                eax, eax

        $sequence_1 = { c707???????? 68???????? ff9688050000 8bf8 3bfb }
            // n = 5, score = 100
            //   c707????????         |                     
            //   68????????           |                     
            //   ff9688050000         | call                dword ptr [esi + 0x588]
            //   8bf8                 | mov                 edi, eax
            //   3bfb                 | cmp                 edi, ebx

        $sequence_2 = { 395dfc 0f84ab000000 8d45f8 50 53 ff75fc 895df8 }
            // n = 7, score = 100
            //   395dfc               | cmp                 dword ptr [ebp - 4], ebx
            //   0f84ab000000         | je                  0xb1
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   895df8               | mov                 dword ptr [ebp - 8], ebx

        $sequence_3 = { ba00000040 8d4df0 c745dc48654400 c745e058654400 c745e468654400 c745e874654400 c745ec80654400 }
            // n = 7, score = 100
            //   ba00000040           | mov                 edx, 0x40000000
            //   8d4df0               | lea                 ecx, [ebp - 0x10]
            //   c745dc48654400       | mov                 dword ptr [ebp - 0x24], 0x446548
            //   c745e058654400       | mov                 dword ptr [ebp - 0x20], 0x446558
            //   c745e468654400       | mov                 dword ptr [ebp - 0x1c], 0x446568
            //   c745e874654400       | mov                 dword ptr [ebp - 0x18], 0x446574
            //   c745ec80654400       | mov                 dword ptr [ebp - 0x14], 0x446580

        $sequence_4 = { eb3a 53 53 ff750c 8d45f0 ff7508 50 }
            // n = 7, score = 100
            //   eb3a                 | jmp                 0x3c
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   50                   | push                eax

        $sequence_5 = { 038150070000 03812c070000 038118070000 0381a0060000 038124060000 038190050000 038130050000 }
            // n = 7, score = 100
            //   038150070000         | add                 eax, dword ptr [ecx + 0x750]
            //   03812c070000         | add                 eax, dword ptr [ecx + 0x72c]
            //   038118070000         | add                 eax, dword ptr [ecx + 0x718]
            //   0381a0060000         | add                 eax, dword ptr [ecx + 0x6a0]
            //   038124060000         | add                 eax, dword ptr [ecx + 0x624]
            //   038190050000         | add                 eax, dword ptr [ecx + 0x590]
            //   038130050000         | add                 eax, dword ptr [ecx + 0x530]

        $sequence_6 = { ff961c070000 83c40c 57 8d45e8 50 ff963c050000 53 }
            // n = 7, score = 100
            //   ff961c070000         | call                dword ptr [esi + 0x71c]
            //   83c40c               | add                 esp, 0xc
            //   57                   | push                edi
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   50                   | push                eax
            //   ff963c050000         | call                dword ptr [esi + 0x53c]
            //   53                   | push                ebx

        $sequence_7 = { 7406 8d4df4 51 ffd0 6a10 8d45e0 53 }
            // n = 7, score = 100
            //   7406                 | je                  8
            //   8d4df4               | lea                 ecx, [ebp - 0xc]
            //   51                   | push                ecx
            //   ffd0                 | call                eax
            //   6a10                 | push                0x10
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   53                   | push                ebx

        $sequence_8 = { 750b 8b07 57 ff5008 e9???????? 8365f800 53 }
            // n = 7, score = 100
            //   750b                 | jne                 0xd
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   57                   | push                edi
            //   ff5008               | call                dword ptr [eax + 8]
            //   e9????????           |                     
            //   8365f800             | and                 dword ptr [ebp - 8], 0
            //   53                   | push                ebx

        $sequence_9 = { 885dff ff9084050000 8b45f8 8b4df8 ff9034060000 8b45f8 }
            // n = 6, score = 100
            //   885dff               | mov                 byte ptr [ebp - 1], bl
            //   ff9084050000         | call                dword ptr [eax + 0x584]
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   ff9034060000         | call                dword ptr [eax + 0x634]
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

    condition:
        7 of them and filesize < 622592
}