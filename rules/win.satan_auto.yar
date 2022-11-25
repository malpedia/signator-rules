rule win_satan_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.satan."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.satan"
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
        $sequence_0 = { 837d0800 7504 32c0 eb75 6a2e }
            // n = 5, score = 100
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   7504                 | jne                 6
            //   32c0                 | xor                 al, al
            //   eb75                 | jmp                 0x77
            //   6a2e                 | push                0x2e

        $sequence_1 = { 83e107 b801000000 d3e0 23d0 7411 8b4dd8 c60100 }
            // n = 7, score = 100
            //   83e107               | and                 ecx, 7
            //   b801000000           | mov                 eax, 1
            //   d3e0                 | shl                 eax, cl
            //   23d0                 | and                 edx, eax
            //   7411                 | je                  0x13
            //   8b4dd8               | mov                 ecx, dword ptr [ebp - 0x28]
            //   c60100               | mov                 byte ptr [ecx], 0

        $sequence_2 = { 8bf8 0f434d0c 56 57 6aff 51 6a00 }
            // n = 7, score = 100
            //   8bf8                 | mov                 edi, eax
            //   0f434d0c             | cmovae              ecx, dword ptr [ebp + 0xc]
            //   56                   | push                esi
            //   57                   | push                edi
            //   6aff                 | push                -1
            //   51                   | push                ecx
            //   6a00                 | push                0

        $sequence_3 = { 83f840 0f8497000000 3d00010000 7448 56 ff751c 8d45a4 }
            // n = 7, score = 100
            //   83f840               | cmp                 eax, 0x40
            //   0f8497000000         | je                  0x9d
            //   3d00010000           | cmp                 eax, 0x100
            //   7448                 | je                  0x4a
            //   56                   | push                esi
            //   ff751c               | push                dword ptr [ebp + 0x1c]
            //   8d45a4               | lea                 eax, [ebp - 0x5c]

        $sequence_4 = { c745f8???????? 85c0 0f84ce000000 8d8d38fdffff c78538fdffff28010000 51 50 }
            // n = 7, score = 100
            //   c745f8????????       |                     
            //   85c0                 | test                eax, eax
            //   0f84ce000000         | je                  0xd4
            //   8d8d38fdffff         | lea                 ecx, [ebp - 0x2c8]
            //   c78538fdffff28010000     | mov    dword ptr [ebp - 0x2c8], 0x128
            //   51                   | push                ecx
            //   50                   | push                eax

        $sequence_5 = { c645ec00 ff75ec c645e800 ff75e8 53 83ec0c }
            // n = 6, score = 100
            //   c645ec00             | mov                 byte ptr [ebp - 0x14], 0
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   c645e800             | mov                 byte ptr [ebp - 0x18], 0
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   53                   | push                ebx
            //   83ec0c               | sub                 esp, 0xc

        $sequence_6 = { 83c404 8975b0 c645fc04 8b4dac 85c9 }
            // n = 5, score = 100
            //   83c404               | add                 esp, 4
            //   8975b0               | mov                 dword ptr [ebp - 0x50], esi
            //   c645fc04             | mov                 byte ptr [ebp - 4], 4
            //   8b4dac               | mov                 ecx, dword ptr [ebp - 0x54]
            //   85c9                 | test                ecx, ecx

        $sequence_7 = { 56 e8???????? 83c40c 8d45f8 50 6800040000 }
            // n = 6, score = 100
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   6800040000           | push                0x400

        $sequence_8 = { 6a01 6a02 ff75bc ffd7 }
            // n = 4, score = 100
            //   6a01                 | push                1
            //   6a02                 | push                2
            //   ff75bc               | push                dword ptr [ebp - 0x44]
            //   ffd7                 | call                edi

        $sequence_9 = { 8b4d08 83e13f 6bd130 8b048540e04700 8a4c1029 884dff 6a00 }
            // n = 7, score = 100
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   83e13f               | and                 ecx, 0x3f
            //   6bd130               | imul                edx, ecx, 0x30
            //   8b048540e04700       | mov                 eax, dword ptr [eax*4 + 0x47e040]
            //   8a4c1029             | mov                 cl, byte ptr [eax + edx + 0x29]
            //   884dff               | mov                 byte ptr [ebp - 1], cl
            //   6a00                 | push                0

    condition:
        7 of them and filesize < 1163264
}