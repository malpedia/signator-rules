rule win_ksl0t_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.ksl0t."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ksl0t"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
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
        $sequence_0 = { 90 304c0438 40 83f80b 72f6 33c0 }
            // n = 6, score = 200
            //   90                   | push                0xa
            //   304c0438             | add                 esp, 0xc
            //   40                   | lea                 ecx, [ebp + 0x1000]
            //   83f80b               | push                ecx
            //   72f6                 | add                 eax, eax
            //   33c0                 | xor                 byte ptr [esp + eax + 0x100], cl

        $sequence_1 = { 68???????? ff15???????? 83c40c e9???????? 6a0a 68???????? }
            // n = 6, score = 200
            //   68????????           |                     
            //   ff15????????         |                     
            //   83c40c               | mov                 ebx, eax
            //   e9????????           |                     
            //   6a0a                 | dec                 eax
            //   68????????           |                     

        $sequence_2 = { e8???????? 48832300 488d05c1c90000 4883c308 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   48832300             | mov                 eax, 0xe
            //   488d05c1c90000       | dec                 eax
            //   4883c308             | lea                 edx, [0xdbf1]

        $sequence_3 = { 488d8c24a0080000 ff15???????? eb1d 4c8d842480040000 }
            // n = 4, score = 200
            //   488d8c24a0080000     | add                 ebx, 8
            //   ff15????????         |                     
            //   eb1d                 | cmp                 dword ptr [esp + 0x14b0], 0
            //   4c8d842480040000     | jne                 0x2e

        $sequence_4 = { ff15???????? 83bc24b014000000 752c ff15???????? }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   83bc24b014000000     | dec                 eax
            //   752c                 | lea                 ecx, [esp + 0x80]
            //   ff15????????         |                     

        $sequence_5 = { 4c8bd8 488b842420040000 4c895810 488d942418030000 488b8c24e0010000 }
            // n = 5, score = 200
            //   4c8bd8               | dec                 eax
            //   488b842420040000     | and                 dword ptr [ebx], 0
            //   4c895810             | dec                 eax
            //   488d942418030000     | lea                 eax, [0xc9c1]
            //   488b8c24e0010000     | dec                 eax

        $sequence_6 = { 50 57 8b5de4 8b03 50 }
            // n = 5, score = 200
            //   50                   | mov                 eax, 0x200
            //   57                   | xor                 edx, edx
            //   8b5de4               | dec                 eax
            //   8b03                 | lea                 ecx, [esp + 0x8a0]
            //   50                   | dec                 esp

        $sequence_7 = { 308c04cc010000 40 83f812 72f3 33c0 }
            // n = 5, score = 200
            //   308c04cc010000       | add                 edx, 0x90
            //   40                   | inc                 ecx
            //   83f812               | mov                 eax, 1
            //   72f3                 | dec                 eax
            //   33c0                 | lea                 ecx, [0xe723]

        $sequence_8 = { 0f8445070000 488d9424b8010000 488b8c2448020000 ff942418040000 4c8bd8 }
            // n = 5, score = 200
            //   0f8445070000         | je                  0x74b
            //   488d9424b8010000     | dec                 eax
            //   488b8c2448020000     | lea                 edx, [esp + 0x1b8]
            //   ff942418040000       | dec                 eax
            //   4c8bd8               | mov                 ecx, dword ptr [esp + 0x248]

        $sequence_9 = { 41b818000000 488d15e8db0000 b92b000000 e8???????? 41b80e000000 488d15f1db0000 }
            // n = 6, score = 200
            //   41b818000000         | call                dword ptr [esp + 0x418]
            //   488d15e8db0000       | dec                 esp
            //   b92b000000           | mov                 ebx, eax
            //   e8????????           |                     
            //   41b80e000000         | inc                 ecx
            //   488d15f1db0000       | mov                 eax, 0x18

        $sequence_10 = { 308c0400010000 40 83f80f 72f3 }
            // n = 4, score = 200
            //   308c0400010000       | lea                 edx, [esp + 0x318]
            //   40                   | dec                 eax
            //   83f80f               | mov                 ecx, dword ptr [esp + 0x1e0]
            //   72f3                 | dec                 eax

        $sequence_11 = { 83ec08 8d0424 50 51 ff15???????? 85c0 741d }
            // n = 7, score = 200
            //   83ec08               | push                eax
            //   8d0424               | push                edi
            //   50                   | mov                 ebx, dword ptr [ebp - 0x1c]
            //   51                   | mov                 eax, dword ptr [ebx]
            //   ff15????????         |                     
            //   85c0                 | push                eax
            //   741d                 | add                 esp, 0xc

        $sequence_12 = { c644241f31 c644242019 c64424213c c644242237 c644242327 c644242434 c644242527 }
            // n = 7, score = 200
            //   c644241f31           | lea                 ecx, [esp + 0x8a0]
            //   c644242019           | jmp                 0x27
            //   c64424213c           | dec                 esp
            //   c644242237           | lea                 eax, [esp + 0x480]
            //   c644242327           | dec                 eax
            //   c644242434           | lea                 edx, [0xc477]
            //   c644242527           | dec                 eax

        $sequence_13 = { c644246e21 c644246f30 c644247038 c644247101 c64424723c }
            // n = 5, score = 200
            //   c644246e21           | mov                 byte ptr [esp + 0x6e], 0x21
            //   c644246f30           | mov                 byte ptr [esp + 0x6f], 0x30
            //   c644247038           | mov                 byte ptr [esp + 0x70], 0x38
            //   c644247101           | mov                 byte ptr [esp + 0x71], 1
            //   c64424723c           | mov                 byte ptr [esp + 0x72], 0x3c

        $sequence_14 = { 488d8c2480000000 ff15???????? 48898424c0140000 41b800020000 33d2 }
            // n = 5, score = 200
            //   488d8c2480000000     | dec                 eax
            //   ff15????????         |                     
            //   48898424c0140000     | lea                 edx, [0xdbe8]
            //   41b800020000         | mov                 ecx, 0x2b
            //   33d2                 | inc                 ecx

        $sequence_15 = { 83c40c 8d8d00100000 51 ff15???????? 03c0 }
            // n = 5, score = 200
            //   83c40c               | mov                 eax, dword ptr [esp + 0x420]
            //   8d8d00100000         | dec                 esp
            //   51                   | mov                 dword ptr [eax + 0x10], ebx
            //   ff15????????         |                     
            //   03c0                 | dec                 eax

    condition:
        7 of them and filesize < 196608
}