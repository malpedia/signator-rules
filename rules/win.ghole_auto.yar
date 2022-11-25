rule win_ghole_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.ghole."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ghole"
        malpedia_rule_date = "20221118"
        malpedia_hash = "e0702e2e6d1d00da65c8a29a4ebacd0a4c59e1af"
        malpedia_version = "20221125"
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
        $sequence_0 = { 31c2 48 8b45c8 48 83c00e 0fb600 0fb6c0 }
            // n = 7, score = 100
            //   31c2                 | xor                 edx, eax
            //   48                   | dec                 eax
            //   8b45c8               | mov                 eax, dword ptr [ebp - 0x38]
            //   48                   | dec                 eax
            //   83c00e               | add                 eax, 0xe
            //   0fb600               | movzx               eax, byte ptr [eax]
            //   0fb6c0               | movzx               eax, al

        $sequence_1 = { 48 8d3d0e6f0000 e8???????? 48 8905???????? 48 8d35706f0000 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   8d3d0e6f0000         | lea                 edi, [0x6f0e]
            //   e8????????           |                     
            //   48                   | dec                 eax
            //   8905????????         |                     
            //   48                   | dec                 eax
            //   8d35706f0000         | lea                 esi, [0x6f70]

        $sequence_2 = { 8b5dc0 48 8b45d0 48 8d1563300000 48 }
            // n = 6, score = 100
            //   8b5dc0               | mov                 ebx, dword ptr [ebp - 0x40]
            //   48                   | dec                 eax
            //   8b45d0               | mov                 eax, dword ptr [ebp - 0x30]
            //   48                   | dec                 eax
            //   8d1563300000         | lea                 edx, [0x3063]
            //   48                   | dec                 eax

        $sequence_3 = { 48 897df8 48 837df800 747a 48 8b45f8 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   897df8               | mov                 dword ptr [ebp - 8], edi
            //   48                   | dec                 eax
            //   837df800             | cmp                 dword ptr [ebp - 8], 0
            //   747a                 | je                  0x7c
            //   48                   | dec                 eax
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

        $sequence_4 = { 48 8b00 48 85c0 0f8412010000 48 8b45e0 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   48                   | dec                 eax
            //   85c0                 | test                eax, eax
            //   0f8412010000         | je                  0x118
            //   48                   | dec                 eax
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]

        $sequence_5 = { 48 8d35bc700000 48 8d3dd26e0000 e8???????? 48 8905???????? }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   8d35bc700000         | lea                 esi, [0x70bc]
            //   48                   | dec                 eax
            //   8d3dd26e0000         | lea                 edi, [0x6ed2]
            //   e8????????           |                     
            //   48                   | dec                 eax
            //   8905????????         |                     

        $sequence_6 = { 48 8975e0 48 8955d8 48 894dd0 48 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi
            //   48                   | dec                 eax
            //   8955d8               | mov                 dword ptr [ebp - 0x28], edx
            //   48                   | dec                 eax
            //   894dd0               | mov                 dword ptr [ebp - 0x30], ecx
            //   48                   | dec                 eax

        $sequence_7 = { ffd3 8945e8 837de800 7407 b8ffffffff eb79 c745ec00000000 }
            // n = 7, score = 100
            //   ffd3                 | call                ebx
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   837de800             | cmp                 dword ptr [ebp - 0x18], 0
            //   7407                 | je                  9
            //   b8ffffffff           | mov                 eax, 0xffffffff
            //   eb79                 | jmp                 0x7b
            //   c745ec00000000       | mov                 dword ptr [ebp - 0x14], 0

        $sequence_8 = { 7538 833d????????00 7424 48 8bcb e8???????? 85c0 }
            // n = 7, score = 100
            //   7538                 | jne                 0x3a
            //   833d????????00       |                     
            //   7424                 | je                  0x26
            //   48                   | dec                 eax
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_9 = { 48 8d148500000000 48 8d05ce660000 8b0402 2500ff0000 31c1 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   8d148500000000       | lea                 edx, [eax*4]
            //   48                   | dec                 eax
            //   8d05ce660000         | lea                 eax, [0x66ce]
            //   8b0402               | mov                 eax, dword ptr [edx + eax]
            //   2500ff0000           | and                 eax, 0xff00
            //   31c1                 | xor                 ecx, eax

    condition:
        7 of them and filesize < 622592
}