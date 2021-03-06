rule win_flying_dutchman_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.flying_dutchman."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.flying_dutchman"
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
        $sequence_0 = { 3b4b08 7507 8bf3 e8???????? 8b4304 69ff48060000 033b }
            // n = 7, score = 100
            //   3b4b08               | cmp                 ecx, dword ptr [ebx + 8]
            //   7507                 | jne                 9
            //   8bf3                 | mov                 esi, ebx
            //   e8????????           |                     
            //   8b4304               | mov                 eax, dword ptr [ebx + 4]
            //   69ff48060000         | imul                edi, edi, 0x648
            //   033b                 | add                 edi, dword ptr [ebx]

        $sequence_1 = { 53 8d44240c 50 ff15???????? eb0a ff7704 8bce }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   8d44240c             | lea                 eax, [esp + 0xc]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   eb0a                 | jmp                 0xc
            //   ff7704               | push                dword ptr [edi + 4]
            //   8bce                 | mov                 ecx, esi

        $sequence_2 = { 8b4508 66893b 668b4008 66894304 33c0 6a0a }
            // n = 6, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   66893b               | mov                 word ptr [ebx], di
            //   668b4008             | mov                 ax, word ptr [eax + 8]
            //   66894304             | mov                 word ptr [ebx + 4], ax
            //   33c0                 | xor                 eax, eax
            //   6a0a                 | push                0xa

        $sequence_3 = { 55 8bec 53 6800200000 33db c7461401000000 e8???????? }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   53                   | push                ebx
            //   6800200000           | push                0x2000
            //   33db                 | xor                 ebx, ebx
            //   c7461401000000       | mov                 dword ptr [esi + 0x14], 1
            //   e8????????           |                     

        $sequence_4 = { 6a00 53 e8???????? 83c40c ff7604 }
            // n = 5, score = 100
            //   6a00                 | push                0
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   ff7604               | push                dword ptr [esi + 4]

        $sequence_5 = { 8903 e8???????? 33c0 5e 40 5b }
            // n = 6, score = 100
            //   8903                 | mov                 dword ptr [ebx], eax
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi
            //   40                   | inc                 eax
            //   5b                   | pop                 ebx

        $sequence_6 = { ff4d0c 8995c0feffff 85c9 0f8e04010000 3c3d }
            // n = 5, score = 100
            //   ff4d0c               | dec                 dword ptr [ebp + 0xc]
            //   8995c0feffff         | mov                 dword ptr [ebp - 0x140], edx
            //   85c9                 | test                ecx, ecx
            //   0f8e04010000         | jle                 0x10a
            //   3c3d                 | cmp                 al, 0x3d

        $sequence_7 = { eb40 57 57 8d442418 50 89742420 }
            // n = 6, score = 100
            //   eb40                 | jmp                 0x42
            //   57                   | push                edi
            //   57                   | push                edi
            //   8d442418             | lea                 eax, [esp + 0x18]
            //   50                   | push                eax
            //   89742420             | mov                 dword ptr [esp + 0x20], esi

        $sequence_8 = { 8d85f0fdffff 50 e8???????? 83c40c 6a44 8d8598fdffff 53 }
            // n = 7, score = 100
            //   8d85f0fdffff         | lea                 eax, [ebp - 0x210]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a44                 | push                0x44
            //   8d8598fdffff         | lea                 eax, [ebp - 0x268]
            //   53                   | push                ebx

        $sequence_9 = { 0f8699000000 8d4702 898530ffffff 8a043e 3c23 756f 38443e01 }
            // n = 7, score = 100
            //   0f8699000000         | jbe                 0x9f
            //   8d4702               | lea                 eax, [edi + 2]
            //   898530ffffff         | mov                 dword ptr [ebp - 0xd0], eax
            //   8a043e               | mov                 al, byte ptr [esi + edi]
            //   3c23                 | cmp                 al, 0x23
            //   756f                 | jne                 0x71
            //   38443e01             | cmp                 byte ptr [esi + edi + 1], al

    condition:
        7 of them and filesize < 276480
}