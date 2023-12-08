rule win_virut_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.virut."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.virut"
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
        $sequence_0 = { 89442418 3bc3 0f8441020000 6801040000 8d8424fc050000 53 50 }
            // n = 7, score = 200
            //   89442418             | mov                 dword ptr [esp + 0x18], eax
            //   3bc3                 | cmp                 eax, ebx
            //   0f8441020000         | je                  0x247
            //   6801040000           | push                0x401
            //   8d8424fc050000       | lea                 eax, [esp + 0x5fc]
            //   53                   | push                ebx
            //   50                   | push                eax

        $sequence_1 = { 33f6 8bca 83c107 3bcb 7e1b }
            // n = 5, score = 200
            //   33f6                 | xor                 esi, esi
            //   8bca                 | mov                 ecx, edx
            //   83c107               | add                 ecx, 7
            //   3bcb                 | cmp                 ecx, ebx
            //   7e1b                 | jle                 0x1d

        $sequence_2 = { 0f8402010000 803f4d 0f85f9000000 807f015a }
            // n = 4, score = 200
            //   0f8402010000         | je                  0x108
            //   803f4d               | cmp                 byte ptr [edi], 0x4d
            //   0f85f9000000         | jne                 0xff
            //   807f015a             | cmp                 byte ptr [edi + 1], 0x5a

        $sequence_3 = { 6a00 59 e30a 6a0a }
            // n = 4, score = 200
            //   6a00                 | push                0
            //   59                   | pop                 ecx
            //   e30a                 | jecxz               0xc
            //   6a0a                 | push                0xa

        $sequence_4 = { ff74241c 6a40 ff15???????? 8bf8 33c0 3bf3 }
            // n = 6, score = 200
            //   ff74241c             | push                dword ptr [esp + 0x1c]
            //   6a40                 | push                0x40
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   33c0                 | xor                 eax, eax
            //   3bf3                 | cmp                 esi, ebx

        $sequence_5 = { 8bf0 3bf3 0f8e82000000 ff74240c 57 56 }
            // n = 6, score = 200
            //   8bf0                 | mov                 esi, eax
            //   3bf3                 | cmp                 esi, ebx
            //   0f8e82000000         | jle                 0x88
            //   ff74240c             | push                dword ptr [esp + 0xc]
            //   57                   | push                edi
            //   56                   | push                esi

        $sequence_6 = { 51 6800040000 8d8c2404060000 51 89442428 }
            // n = 5, score = 200
            //   51                   | push                ecx
            //   6800040000           | push                0x400
            //   8d8c2404060000       | lea                 ecx, [esp + 0x604]
            //   51                   | push                ecx
            //   89442428             | mov                 dword ptr [esp + 0x28], eax

        $sequence_7 = { 8bcb f3a6 61 7405 }
            // n = 4, score = 200
            //   8bcb                 | mov                 ecx, ebx
            //   f3a6                 | repe cmpsb          byte ptr [esi], byte ptr es:[edi]
            //   61                   | popal               
            //   7405                 | je                  7

        $sequence_8 = { 8bd4 6a00 52 ff32 }
            // n = 4, score = 200
            //   8bd4                 | mov                 edx, esp
            //   6a00                 | push                0
            //   52                   | push                edx
            //   ff32                 | push                dword ptr [edx]

        $sequence_9 = { 33d2 8bcf 52 f6d9 52 83e103 6a40 }
            // n = 7, score = 200
            //   33d2                 | xor                 edx, edx
            //   8bcf                 | mov                 ecx, edi
            //   52                   | push                edx
            //   f6d9                 | neg                 cl
            //   52                   | push                edx
            //   83e103               | and                 ecx, 3
            //   6a40                 | push                0x40

        $sequence_10 = { 6800030084 51 51 56 }
            // n = 4, score = 200
            //   6800030084           | push                0x84000300
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   56                   | push                esi

        $sequence_11 = { 49 4e 45 54 2e44 4c }
            // n = 6, score = 200
            //   49                   | dec                 ecx
            //   4e                   | dec                 esi
            //   45                   | inc                 ebp
            //   54                   | push                esp
            //   2e44                 | inc                 esp
            //   4c                   | dec                 esp

        $sequence_12 = { 53 8d442444 50 8d8424e0020000 50 ffd6 }
            // n = 6, score = 200
            //   53                   | push                ebx
            //   8d442444             | lea                 eax, [esp + 0x44]
            //   50                   | push                eax
            //   8d8424e0020000       | lea                 eax, [esp + 0x2e0]
            //   50                   | push                eax
            //   ffd6                 | call                esi

        $sequence_13 = { eb49 395c240c 7449 33c0 395c240c 7e24 }
            // n = 6, score = 200
            //   eb49                 | jmp                 0x4b
            //   395c240c             | cmp                 dword ptr [esp + 0xc], ebx
            //   7449                 | je                  0x4b
            //   33c0                 | xor                 eax, eax
            //   395c240c             | cmp                 dword ptr [esp + 0xc], ebx
            //   7e24                 | jle                 0x26

        $sequence_14 = { 6a10 59 f3ab 50 50 }
            // n = 5, score = 200
            //   6a10                 | push                0x10
            //   59                   | pop                 ecx
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   50                   | push                eax
            //   50                   | push                eax

        $sequence_15 = { 66ab 8d4704 ab 32e4 ac }
            // n = 5, score = 200
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   8d4704               | lea                 eax, [edi + 4]
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   32e4                 | xor                 ah, ah
            //   ac                   | lodsb               al, byte ptr [esi]

    condition:
        7 of them and filesize < 98304
}