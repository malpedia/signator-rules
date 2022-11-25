rule win_mongall_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.mongall."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mongall"
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
        $sequence_0 = { 57 8d3c85703a4100 833f00 bb00100000 7520 53 e8???????? }
            // n = 7, score = 100
            //   57                   | push                edi
            //   8d3c85703a4100       | lea                 edi, [eax*4 + 0x413a70]
            //   833f00               | cmp                 dword ptr [edi], 0
            //   bb00100000           | mov                 ebx, 0x1000
            //   7520                 | jne                 0x22
            //   53                   | push                ebx
            //   e8????????           |                     

        $sequence_1 = { 7440 80f96c 7414 80f977 0f8579080000 }
            // n = 5, score = 100
            //   7440                 | je                  0x42
            //   80f96c               | cmp                 cl, 0x6c
            //   7414                 | je                  0x16
            //   80f977               | cmp                 cl, 0x77
            //   0f8579080000         | jne                 0x87f

        $sequence_2 = { 8b9de0fdffff 7457 85db 7e53 8bb5d8fdffff 0fb706 50 }
            // n = 7, score = 100
            //   8b9de0fdffff         | mov                 ebx, dword ptr [ebp - 0x220]
            //   7457                 | je                  0x59
            //   85db                 | test                ebx, ebx
            //   7e53                 | jle                 0x55
            //   8bb5d8fdffff         | mov                 esi, dword ptr [ebp - 0x228]
            //   0fb706               | movzx               eax, word ptr [esi]
            //   50                   | push                eax

        $sequence_3 = { 7506 2185d0fdffff 8d7df3 8b85e8fdffff ff8de8fdffff }
            // n = 5, score = 100
            //   7506                 | jne                 8
            //   2185d0fdffff         | and                 dword ptr [ebp - 0x230], eax
            //   8d7df3               | lea                 edi, [ebp - 0xd]
            //   8b85e8fdffff         | mov                 eax, dword ptr [ebp - 0x218]
            //   ff8de8fdffff         | dec                 dword ptr [ebp - 0x218]

        $sequence_4 = { 57 e8???????? 8b45fc 50 6a00 57 e8???????? }
            // n = 7, score = 100
            //   57                   | push                edi
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_5 = { 33ff 33f6 3b5df8 7d2e 8b4d08 }
            // n = 5, score = 100
            //   33ff                 | xor                 edi, edi
            //   33f6                 | xor                 esi, esi
            //   3b5df8               | cmp                 ebx, dword ptr [ebp - 8]
            //   7d2e                 | jge                 0x30
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]

        $sequence_6 = { 8b5bfc 899dd8fdffff 0f84a6040000 85db 750c 8b1d???????? 899dd8fdffff }
            // n = 7, score = 100
            //   8b5bfc               | mov                 ebx, dword ptr [ebx - 4]
            //   899dd8fdffff         | mov                 dword ptr [ebp - 0x228], ebx
            //   0f84a6040000         | je                  0x4ac
            //   85db                 | test                ebx, ebx
            //   750c                 | jne                 0xe
            //   8b1d????????         |                     
            //   899dd8fdffff         | mov                 dword ptr [ebp - 0x228], ebx

        $sequence_7 = { 8bf8 99 83e203 03c2 c1f802 }
            // n = 5, score = 100
            //   8bf8                 | mov                 edi, eax
            //   99                   | cdq                 
            //   83e203               | and                 edx, 3
            //   03c2                 | add                 eax, edx
            //   c1f802               | sar                 eax, 2

        $sequence_8 = { 33c9 b03d 33db 897dfc 894df8 384432ff 750a }
            // n = 7, score = 100
            //   33c9                 | xor                 ecx, ecx
            //   b03d                 | mov                 al, 0x3d
            //   33db                 | xor                 ebx, ebx
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   384432ff             | cmp                 byte ptr [edx + esi - 1], al
            //   750a                 | jne                 0xc

        $sequence_9 = { eb14 8d95f8fdffff 68???????? 52 e8???????? 83c408 68???????? }
            // n = 7, score = 100
            //   eb14                 | jmp                 0x16
            //   8d95f8fdffff         | lea                 edx, [ebp - 0x208]
            //   68????????           |                     
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   68????????           |                     

    condition:
        7 of them and filesize < 199680
}