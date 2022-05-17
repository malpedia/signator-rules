rule win_thunderx_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.thunderx."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.thunderx"
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
        $sequence_0 = { 8d4c240c e8???????? 8b74240c eb0a 8bce e8???????? }
            // n = 6, score = 200
            //   8d4c240c             | lea                 ecx, [esp + 0xc]
            //   e8????????           |                     
            //   8b74240c             | mov                 esi, dword ptr [esp + 0xc]
            //   eb0a                 | jmp                 0xc
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_1 = { b8???????? 0f4305???????? 50 56 ff15???????? 85c0 7462 }
            // n = 7, score = 200
            //   b8????????           |                     
            //   0f4305????????       |                     
            //   50                   | push                eax
            //   56                   | push                esi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7462                 | je                  0x64

        $sequence_2 = { 50 8d4db4 e8???????? 8d4dcc e8???????? c645fc01 }
            // n = 6, score = 200
            //   50                   | push                eax
            //   8d4db4               | lea                 ecx, [ebp - 0x4c]
            //   e8????????           |                     
            //   8d4dcc               | lea                 ecx, [ebp - 0x34]
            //   e8????????           |                     
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1

        $sequence_3 = { 8b45a8 03c2 89559c 6a0d 50 e8???????? 8b4d90 }
            // n = 7, score = 200
            //   8b45a8               | mov                 eax, dword ptr [ebp - 0x58]
            //   03c2                 | add                 eax, edx
            //   89559c               | mov                 dword ptr [ebp - 0x64], edx
            //   6a0d                 | push                0xd
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b4d90               | mov                 ecx, dword ptr [ebp - 0x70]

        $sequence_4 = { 8bc6 7202 8b06 0fb6441801 8d4dd8 50 }
            // n = 6, score = 200
            //   8bc6                 | mov                 eax, esi
            //   7202                 | jb                  4
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   0fb6441801           | movzx               eax, byte ptr [eax + ebx + 1]
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   50                   | push                eax

        $sequence_5 = { 899d54fdffff e8???????? 83fbff 0f840d010000 8d8584fdffff 68???????? 50 }
            // n = 7, score = 200
            //   899d54fdffff         | mov                 dword ptr [ebp - 0x2ac], ebx
            //   e8????????           |                     
            //   83fbff               | cmp                 ebx, -1
            //   0f840d010000         | je                  0x113
            //   8d8584fdffff         | lea                 eax, [ebp - 0x27c]
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_6 = { 8d45e8 897de4 50 8d45e4 897de8 50 ff35???????? }
            // n = 7, score = 200
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   897de4               | mov                 dword ptr [ebp - 0x1c], edi
            //   50                   | push                eax
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   897de8               | mov                 dword ptr [ebp - 0x18], edi
            //   50                   | push                eax
            //   ff35????????         |                     

        $sequence_7 = { 397c2410 7704 8b7c2410 51 57 8d4c2444 }
            // n = 6, score = 200
            //   397c2410             | cmp                 dword ptr [esp + 0x10], edi
            //   7704                 | ja                  6
            //   8b7c2410             | mov                 edi, dword ptr [esp + 0x10]
            //   51                   | push                ecx
            //   57                   | push                edi
            //   8d4c2444             | lea                 ecx, [esp + 0x44]

        $sequence_8 = { e8???????? 83c40c 8bc3 837b1410 7202 8b03 ff7310 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8bc3                 | mov                 eax, ebx
            //   837b1410             | cmp                 dword ptr [ebx + 0x14], 0x10
            //   7202                 | jb                  4
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   ff7310               | push                dword ptr [ebx + 0x10]

        $sequence_9 = { 7415 8d45e4 8bcf 50 e8???????? 8d4de4 }
            // n = 6, score = 200
            //   7415                 | je                  0x17
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   8bcf                 | mov                 ecx, edi
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]

    condition:
        7 of them and filesize < 319488
}