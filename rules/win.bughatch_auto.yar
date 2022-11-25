rule win_bughatch_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.bughatch."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bughatch"
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
        $sequence_0 = { b901000000 6bd100 c68415ecfaffff00 8b4508 8945f4 837df400 7408 }
            // n = 7, score = 100
            //   b901000000           | mov                 ecx, 1
            //   6bd100               | imul                edx, ecx, 0
            //   c68415ecfaffff00     | mov                 byte ptr [ebp + edx - 0x514], 0
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   837df400             | cmp                 dword ptr [ebp - 0xc], 0
            //   7408                 | je                  0xa

        $sequence_1 = { 48 837c247800 741b 48 8b442440 8b4028 48 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   837c247800           | cmp                 dword ptr [esp + 0x78], 0
            //   741b                 | je                  0x1d
            //   48                   | dec                 eax
            //   8b442440             | mov                 eax, dword ptr [esp + 0x40]
            //   8b4028               | mov                 eax, dword ptr [eax + 0x28]
            //   48                   | dec                 eax

        $sequence_2 = { 0fb75102 8d441008 8b4d08 0fb75104 03c2 8b4d08 }
            // n = 6, score = 100
            //   0fb75102             | movzx               edx, word ptr [ecx + 2]
            //   8d441008             | lea                 eax, [eax + edx + 8]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   0fb75104             | movzx               edx, word ptr [ecx + 4]
            //   03c2                 | add                 eax, edx
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]

        $sequence_3 = { ff15???????? 837d2400 7437 837d2800 7431 8b452c 50 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   837d2400             | cmp                 dword ptr [ebp + 0x24], 0
            //   7437                 | je                  0x39
            //   837d2800             | cmp                 dword ptr [ebp + 0x28], 0
            //   7431                 | je                  0x33
            //   8b452c               | mov                 eax, dword ptr [ebp + 0x2c]
            //   50                   | push                eax

        $sequence_4 = { e8???????? 83c404 8945e4 8b4d08 83790c00 7412 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   83790c00             | cmp                 dword ptr [ecx + 0xc], 0
            //   7412                 | je                  0x14

        $sequence_5 = { 7427 8b4df8 51 8b55e8 }
            // n = 4, score = 100
            //   7427                 | je                  0x29
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   51                   | push                ecx
            //   8b55e8               | mov                 edx, dword ptr [ebp - 0x18]

        $sequence_6 = { 8b4804 034de0 8b5510 894a04 eb09 c745f400000000 eb02 }
            // n = 7, score = 100
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   034de0               | add                 ecx, dword ptr [ebp - 0x20]
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   894a04               | mov                 dword ptr [edx + 4], ecx
            //   eb09                 | jmp                 0xb
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   eb02                 | jmp                 4

        $sequence_7 = { 7507 33c0 e9???????? 668b4da8 66894df0 }
            // n = 5, score = 100
            //   7507                 | jne                 9
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   668b4da8             | mov                 cx, word ptr [ebp - 0x58]
            //   66894df0             | mov                 word ptr [ebp - 0x10], cx

        $sequence_8 = { e8???????? 8b4d08 8b5008 89510a }
            // n = 4, score = 100
            //   e8????????           |                     
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b5008               | mov                 edx, dword ptr [eax + 8]
            //   89510a               | mov                 dword ptr [ecx + 0xa], edx

        $sequence_9 = { 8b45f0 8945f4 837df400 7504 33c0 eb0a }
            // n = 6, score = 100
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   837df400             | cmp                 dword ptr [ebp - 0xc], 0
            //   7504                 | jne                 6
            //   33c0                 | xor                 eax, eax
            //   eb0a                 | jmp                 0xc

    condition:
        7 of them and filesize < 75776
}