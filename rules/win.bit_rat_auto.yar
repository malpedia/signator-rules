rule win_bit_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.bit_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bit_rat"
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
        $sequence_0 = { ffd0 8b4d0c 83c404 837e2400 8b5510 0f8f3dffffff 7c0a }
            // n = 7, score = 200
            //   ffd0                 | call                eax
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   83c404               | add                 esp, 4
            //   837e2400             | cmp                 dword ptr [esi + 0x24], 0
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   0f8f3dffffff         | jg                  0xffffff43
            //   7c0a                 | jl                  0xc

        $sequence_1 = { c7400400000000 5e 5f 33c0 5b 8be5 5d }
            // n = 7, score = 200
            //   c7400400000000       | mov                 dword ptr [eax + 4], 0
            //   5e                   | pop                 esi
            //   5f                   | pop                 edi
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp

        $sequence_2 = { 5d c3 3b5734 7221 7705 3b4f30 761a }
            // n = 7, score = 200
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   3b5734               | cmp                 edx, dword ptr [edi + 0x34]
            //   7221                 | jb                  0x23
            //   7705                 | ja                  7
            //   3b4f30               | cmp                 ecx, dword ptr [edi + 0x30]
            //   761a                 | jbe                 0x1c

        $sequence_3 = { 8b4518 8d6b01 f727 8bf8 037c2410 83d200 39742410 }
            // n = 7, score = 200
            //   8b4518               | mov                 eax, dword ptr [ebp + 0x18]
            //   8d6b01               | lea                 ebp, [ebx + 1]
            //   f727                 | mul                 dword ptr [edi]
            //   8bf8                 | mov                 edi, eax
            //   037c2410             | add                 edi, dword ptr [esp + 0x10]
            //   83d200               | adc                 edx, 0
            //   39742410             | cmp                 dword ptr [esp + 0x10], esi

        $sequence_4 = { eb05 bb03000000 8b7508 8bcf 8bd6 e8???????? 83f8ff }
            // n = 7, score = 200
            //   eb05                 | jmp                 7
            //   bb03000000           | mov                 ebx, 3
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   8bcf                 | mov                 ecx, edi
            //   8bd6                 | mov                 edx, esi
            //   e8????????           |                     
            //   83f8ff               | cmp                 eax, -1

        $sequence_5 = { 894704 8bcb e8???????? 33c0 5f 5e }
            // n = 6, score = 200
            //   894704               | mov                 dword ptr [edi + 4], eax
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_6 = { c3 668b5710 8b4df0 6800030000 ff7704 e8???????? 83c408 }
            // n = 7, score = 200
            //   c3                   | ret                 
            //   668b5710             | mov                 dx, word ptr [edi + 0x10]
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   6800030000           | push                0x300
            //   ff7704               | push                dword ptr [edi + 4]
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_7 = { 8b7e08 85ff 743e 897df0 c745fc01000000 8d4f50 894dec }
            // n = 7, score = 200
            //   8b7e08               | mov                 edi, dword ptr [esi + 8]
            //   85ff                 | test                edi, edi
            //   743e                 | je                  0x40
            //   897df0               | mov                 dword ptr [ebp - 0x10], edi
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   8d4f50               | lea                 ecx, [edi + 0x50]
            //   894dec               | mov                 dword ptr [ebp - 0x14], ecx

        $sequence_8 = { e8???????? 83c404 8d45a0 8d4dd8 50 e8???????? 8b4d98 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8d45a0               | lea                 eax, [ebp - 0x60]
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b4d98               | mov                 ecx, dword ptr [ebp - 0x68]

        $sequence_9 = { 7206 837830ff 730c 83782c00 7706 837828ff 7206 }
            // n = 7, score = 200
            //   7206                 | jb                  8
            //   837830ff             | cmp                 dword ptr [eax + 0x30], -1
            //   730c                 | jae                 0xe
            //   83782c00             | cmp                 dword ptr [eax + 0x2c], 0
            //   7706                 | ja                  8
            //   837828ff             | cmp                 dword ptr [eax + 0x28], -1
            //   7206                 | jb                  8

    condition:
        7 of them and filesize < 19405824
}