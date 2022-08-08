rule win_unidentified_092_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-08-05"
        version = "1"
        description = "Detects win.unidentified_092."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_092"
        malpedia_rule_date = "20220805"
        malpedia_hash = "6ec06c64bcfdbeda64eff021c766b4ce34542b71"
        malpedia_version = "20220808"
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
        $sequence_0 = { 8bc1 03d6 234dfc 8bf7 }
            // n = 4, score = 100
            //   8bc1                 | mov                 eax, ecx
            //   03d6                 | add                 edx, esi
            //   234dfc               | and                 ecx, dword ptr [ebp - 4]
            //   8bf7                 | mov                 esi, edi

        $sequence_1 = { 8d85d0fdffff 50 8d8598fdffff 50 6a00 ffd6 8d85c0fdffff }
            // n = 7, score = 100
            //   8d85d0fdffff         | lea                 eax, [ebp - 0x230]
            //   50                   | push                eax
            //   8d8598fdffff         | lea                 eax, [ebp - 0x268]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ffd6                 | call                esi
            //   8d85c0fdffff         | lea                 eax, [ebp - 0x240]

        $sequence_2 = { 8b0d???????? 89048d485e0310 5d c3 55 8bec ff7508 }
            // n = 7, score = 100
            //   8b0d????????         |                     
            //   89048d485e0310       | mov                 dword ptr [ecx*4 + 0x10035e48], eax
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_3 = { 894df4 8bcb 23cf 094df4 0155f4 8b55dc 8bf2 }
            // n = 7, score = 100
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   8bcb                 | mov                 ecx, ebx
            //   23cf                 | and                 ecx, edi
            //   094df4               | or                  dword ptr [ebp - 0xc], ecx
            //   0155f4               | add                 dword ptr [ebp - 0xc], edx
            //   8b55dc               | mov                 edx, dword ptr [ebp - 0x24]
            //   8bf2                 | mov                 esi, edx

        $sequence_4 = { c1e002 50 8b85a4f8ffff 0fb70485bca70210 8d0485b89e0210 50 8d8590faffff }
            // n = 7, score = 100
            //   c1e002               | shl                 eax, 2
            //   50                   | push                eax
            //   8b85a4f8ffff         | mov                 eax, dword ptr [ebp - 0x75c]
            //   0fb70485bca70210     | movzx               eax, word ptr [eax*4 + 0x1002a7bc]
            //   8d0485b89e0210       | lea                 eax, [eax*4 + 0x10029eb8]
            //   50                   | push                eax
            //   8d8590faffff         | lea                 eax, [ebp - 0x570]

        $sequence_5 = { 8b41fc 3bc1 0f8351050000 2bc8 83f904 0f8246050000 }
            // n = 6, score = 100
            //   8b41fc               | mov                 eax, dword ptr [ecx - 4]
            //   3bc1                 | cmp                 eax, ecx
            //   0f8351050000         | jae                 0x557
            //   2bc8                 | sub                 ecx, eax
            //   83f904               | cmp                 ecx, 4
            //   0f8246050000         | jb                  0x54c

        $sequence_6 = { 722a f6c11f 0f85fae3ffff 8b41fc 3bc1 0f83efe3ffff }
            // n = 6, score = 100
            //   722a                 | jb                  0x2c
            //   f6c11f               | test                cl, 0x1f
            //   0f85fae3ffff         | jne                 0xffffe400
            //   8b41fc               | mov                 eax, dword ptr [ecx - 4]
            //   3bc1                 | cmp                 eax, ecx
            //   0f83efe3ffff         | jae                 0xffffe3f5

        $sequence_7 = { 884a07 8bce 50 c1ef08 e8???????? 83fb40 }
            // n = 6, score = 100
            //   884a07               | mov                 byte ptr [edx + 7], cl
            //   8bce                 | mov                 ecx, esi
            //   50                   | push                eax
            //   c1ef08               | shr                 edi, 8
            //   e8????????           |                     
            //   83fb40               | cmp                 ebx, 0x40

        $sequence_8 = { 660ff2dd 660fd2cd 660febd9 0f115c17e0 83e901 7586 8b7de0 }
            // n = 7, score = 100
            //   660ff2dd             | pslld               xmm3, xmm5
            //   660fd2cd             | psrld               xmm1, xmm5
            //   660febd9             | por                 xmm3, xmm1
            //   0f115c17e0           | movups              xmmword ptr [edi + edx - 0x20], xmm3
            //   83e901               | sub                 ecx, 1
            //   7586                 | jne                 0xffffff88
            //   8b7de0               | mov                 edi, dword ptr [ebp - 0x20]

        $sequence_9 = { e8???????? 50 ff15???????? 8d8dccf5ffff 85c0 7410 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d8dccf5ffff         | lea                 ecx, [ebp - 0xa34]
            //   85c0                 | test                eax, eax
            //   7410                 | je                  0x12

    condition:
        7 of them and filesize < 10202112
}