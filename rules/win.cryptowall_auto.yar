rule win_cryptowall_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.cryptowall."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cryptowall"
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
        $sequence_0 = { 89450c eb04 33c0 eb11 8b4d10 83c102 894d10 }
            // n = 7, score = 2100
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   eb04                 | jmp                 6
            //   33c0                 | xor                 eax, eax
            //   eb11                 | jmp                 0x13
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   83c102               | add                 ecx, 2
            //   894d10               | mov                 dword ptr [ebp + 0x10], ecx

        $sequence_1 = { c645ee7c c645ef25 c645f073 c645f17d }
            // n = 4, score = 2100
            //   c645ee7c             | mov                 byte ptr [ebp - 0x12], 0x7c
            //   c645ef25             | mov                 byte ptr [ebp - 0x11], 0x25
            //   c645f073             | mov                 byte ptr [ebp - 0x10], 0x73
            //   c645f17d             | mov                 byte ptr [ebp - 0xf], 0x7d

        $sequence_2 = { b80d0000c0 e9???????? 837d1400 7507 b80d0000c0 }
            // n = 5, score = 2100
            //   b80d0000c0           | mov                 eax, 0xc000000d
            //   e9????????           |                     
            //   837d1400             | cmp                 dword ptr [ebp + 0x14], 0
            //   7507                 | jne                 9
            //   b80d0000c0           | mov                 eax, 0xc000000d

        $sequence_3 = { 51 e8???????? 8b502c ffd2 }
            // n = 4, score = 2100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8b502c               | mov                 edx, dword ptr [eax + 0x2c]
            //   ffd2                 | call                edx

        $sequence_4 = { 8b45fc 2d00080000 8945fc ebe5 8b45fc 8be5 }
            // n = 6, score = 2100
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   2d00080000           | sub                 eax, 0x800
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   ebe5                 | jmp                 0xffffffe7
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8be5                 | mov                 esp, ebp

        $sequence_5 = { e8???????? 83c408 8b0d???????? 898164010000 }
            // n = 4, score = 2100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b0d????????         |                     
            //   898164010000         | mov                 dword ptr [ecx + 0x164], eax

        $sequence_6 = { 55 8bec 51 837d0800 7441 837d0c00 }
            // n = 6, score = 2100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   7441                 | je                  0x43
            //   837d0c00             | cmp                 dword ptr [ebp + 0xc], 0

        $sequence_7 = { 7d26 68e8030000 6a00 e8???????? 83c408 99 }
            // n = 6, score = 2100
            //   7d26                 | jge                 0x28
            //   68e8030000           | push                0x3e8
            //   6a00                 | push                0
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   99                   | cdq                 

        $sequence_8 = { ebae eb96 8b450c 8b4df4 }
            // n = 4, score = 2100
            //   ebae                 | jmp                 0xffffffb0
            //   eb96                 | jmp                 0xffffff98
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_9 = { 6a00 8b4508 50 6aff }
            // n = 4, score = 2100
            //   6a00                 | push                0
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   50                   | push                eax
            //   6aff                 | push                -1

    condition:
        7 of them and filesize < 417792
}