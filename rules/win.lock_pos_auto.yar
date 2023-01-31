rule win_lock_pos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.lock_pos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lock_pos"
        malpedia_rule_date = "20230124"
        malpedia_hash = "2ee0eebba83dce3d019a90519f2f972c0fcf9686"
        malpedia_version = "20230125"
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
        $sequence_0 = { 8bec 8b4508 8b0d???????? 8b0481 }
            // n = 4, score = 400
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b0d????????         |                     
            //   8b0481               | mov                 eax, dword ptr [ecx + eax*4]

        $sequence_1 = { 8bec 837d0800 7704 33c0 }
            // n = 4, score = 400
            //   8bec                 | mov                 ebp, esp
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   7704                 | ja                  6
            //   33c0                 | xor                 eax, eax

        $sequence_2 = { 8d85f8fdffff 50 6a00 6a00 6a23 }
            // n = 5, score = 300
            //   8d85f8fdffff         | lea                 eax, [ebp - 0x208]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a23                 | push                0x23

        $sequence_3 = { 6a23 6a00 ff15???????? 8d8df8fdffff }
            // n = 4, score = 300
            //   6a23                 | push                0x23
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8d8df8fdffff         | lea                 ecx, [ebp - 0x208]

        $sequence_4 = { 55 8bec 81eca4040000 56 }
            // n = 4, score = 300
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81eca4040000         | sub                 esp, 0x4a4
            //   56                   | push                esi

        $sequence_5 = { 33d2 b910000000 f7f1 8b45e0 0355ec 8d0cc2 894dec }
            // n = 7, score = 200
            //   33d2                 | xor                 edx, edx
            //   b910000000           | mov                 ecx, 0x10
            //   f7f1                 | div                 ecx
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   0355ec               | add                 edx, dword ptr [ebp - 0x14]
            //   8d0cc2               | lea                 ecx, [edx + eax*8]
            //   894dec               | mov                 dword ptr [ebp - 0x14], ecx

        $sequence_6 = { b901000000 85c9 7446 8b55d4 0fb702 }
            // n = 5, score = 200
            //   b901000000           | mov                 ecx, 1
            //   85c9                 | test                ecx, ecx
            //   7446                 | je                  0x48
            //   8b55d4               | mov                 edx, dword ptr [ebp - 0x2c]
            //   0fb702               | movzx               eax, word ptr [edx]

        $sequence_7 = { 8d45f4 50 ff75fc 895df4 }
            // n = 4, score = 200
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   895df4               | mov                 dword ptr [ebp - 0xc], ebx

        $sequence_8 = { e8???????? 84c0 7517 6a04 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7517                 | jne                 0x19
            //   6a04                 | push                4

        $sequence_9 = { eb57 8b45f4 50 e8???????? 83c404 }
            // n = 5, score = 200
            //   eb57                 | jmp                 0x59
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_10 = { 5e 57 53 e8???????? 53 e8???????? 83c40c }
            // n = 7, score = 200
            //   5e                   | pop                 esi
            //   57                   | push                edi
            //   53                   | push                ebx
            //   e8????????           |                     
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_11 = { 8955e0 7502 ebc7 8b45fc 668b08 66894de4 }
            // n = 6, score = 200
            //   8955e0               | mov                 dword ptr [ebp - 0x20], edx
            //   7502                 | jne                 4
            //   ebc7                 | jmp                 0xffffffc9
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   668b08               | mov                 cx, word ptr [eax]
            //   66894de4             | mov                 word ptr [ebp - 0x1c], cx

        $sequence_12 = { 8b55dc 8b45dc 83e801 8945dc 85d2 0f843a010000 }
            // n = 6, score = 200
            //   8b55dc               | mov                 edx, dword ptr [ebp - 0x24]
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   83e801               | sub                 eax, 1
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   85d2                 | test                edx, edx
            //   0f843a010000         | je                  0x140

    condition:
        7 of them and filesize < 319488
}