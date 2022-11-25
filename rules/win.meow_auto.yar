rule win_meow_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.meow."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.meow"
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
        $sequence_0 = { c685b8feffff1e c685b9feffff75 c685bafeffff1e c685bbfeffff02 c685bcfeffff1e c685bdfeffff54 c685befeffff1e }
            // n = 7, score = 100
            //   c685b8feffff1e       | mov                 byte ptr [ebp - 0x148], 0x1e
            //   c685b9feffff75       | mov                 byte ptr [ebp - 0x147], 0x75
            //   c685bafeffff1e       | mov                 byte ptr [ebp - 0x146], 0x1e
            //   c685bbfeffff02       | mov                 byte ptr [ebp - 0x145], 2
            //   c685bcfeffff1e       | mov                 byte ptr [ebp - 0x144], 0x1e
            //   c685bdfeffff54       | mov                 byte ptr [ebp - 0x143], 0x54
            //   c685befeffff1e       | mov                 byte ptr [ebp - 0x142], 0x1e

        $sequence_1 = { 0f1106 f30f7e4010 c7401000000000 660fd64610 c7401407000000 668908 }
            // n = 6, score = 100
            //   0f1106               | movups              xmmword ptr [esi], xmm0
            //   f30f7e4010           | movq                xmm0, qword ptr [eax + 0x10]
            //   c7401000000000       | mov                 dword ptr [eax + 0x10], 0
            //   660fd64610           | movq                qword ptr [esi + 0x10], xmm0
            //   c7401407000000       | mov                 dword ptr [eax + 0x14], 7
            //   668908               | mov                 word ptr [eax], cx

        $sequence_2 = { 8d7601 0fb6c8 83e929 8bc1 c1e004 2bc1 99 }
            // n = 7, score = 100
            //   8d7601               | lea                 esi, [esi + 1]
            //   0fb6c8               | movzx               ecx, al
            //   83e929               | sub                 ecx, 0x29
            //   8bc1                 | mov                 eax, ecx
            //   c1e004               | shl                 eax, 4
            //   2bc1                 | sub                 eax, ecx
            //   99                   | cdq                 

        $sequence_3 = { c21000 8b4c2464 b801000000 5f 5e 5b }
            // n = 6, score = 100
            //   c21000               | ret                 0x10
            //   8b4c2464             | mov                 ecx, dword ptr [esp + 0x64]
            //   b801000000           | mov                 eax, 1
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_4 = { 8b858cf7ffff 99 f7fb 85d2 7460 8b8d8cf7ffff 8b85ccf7ffff }
            // n = 7, score = 100
            //   8b858cf7ffff         | mov                 eax, dword ptr [ebp - 0x874]
            //   99                   | cdq                 
            //   f7fb                 | idiv                ebx
            //   85d2                 | test                edx, edx
            //   7460                 | je                  0x62
            //   8b8d8cf7ffff         | mov                 ecx, dword ptr [ebp - 0x874]
            //   8b85ccf7ffff         | mov                 eax, dword ptr [ebp - 0x834]

        $sequence_5 = { c68545f8ffff0e c68546f8ffff2a c68547f8ffff36 c68548f8ffff2a c68549f8ffff74 c6854af8ffff2a }
            // n = 6, score = 100
            //   c68545f8ffff0e       | mov                 byte ptr [ebp - 0x7bb], 0xe
            //   c68546f8ffff2a       | mov                 byte ptr [ebp - 0x7ba], 0x2a
            //   c68547f8ffff36       | mov                 byte ptr [ebp - 0x7b9], 0x36
            //   c68548f8ffff2a       | mov                 byte ptr [ebp - 0x7b8], 0x2a
            //   c68549f8ffff74       | mov                 byte ptr [ebp - 0x7b7], 0x74
            //   c6854af8ffff2a       | mov                 byte ptr [ebp - 0x7b6], 0x2a

        $sequence_6 = { 0f434508 8d4df9 51 52 50 }
            // n = 5, score = 100
            //   0f434508             | cmovae              eax, dword ptr [ebp + 8]
            //   8d4df9               | lea                 ecx, [ebp - 7]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   50                   | push                eax

        $sequence_7 = { bf0a000000 8bce 8d5f75 8a01 8d4901 0fb6c0 83e824 }
            // n = 7, score = 100
            //   bf0a000000           | mov                 edi, 0xa
            //   8bce                 | mov                 ecx, esi
            //   8d5f75               | lea                 ebx, [edi + 0x75]
            //   8a01                 | mov                 al, byte ptr [ecx]
            //   8d4901               | lea                 ecx, [ecx + 1]
            //   0fb6c0               | movzx               eax, al
            //   83e824               | sub                 eax, 0x24

        $sequence_8 = { 99 f7fe 88540dbd 41 83f90c 72de 6a04 }
            // n = 7, score = 100
            //   99                   | cdq                 
            //   f7fe                 | idiv                esi
            //   88540dbd             | mov                 byte ptr [ebp + ecx - 0x43], dl
            //   41                   | inc                 ecx
            //   83f90c               | cmp                 ecx, 0xc
            //   72de                 | jb                  0xffffffe0
            //   6a04                 | push                4

        $sequence_9 = { 8d7b75 0f1f4000 8a06 8d7601 0fb6c0 b929000000 }
            // n = 6, score = 100
            //   8d7b75               | lea                 edi, [ebx + 0x75]
            //   0f1f4000             | nop                 dword ptr [eax]
            //   8a06                 | mov                 al, byte ptr [esi]
            //   8d7601               | lea                 esi, [esi + 1]
            //   0fb6c0               | movzx               eax, al
            //   b929000000           | mov                 ecx, 0x29

    condition:
        7 of them and filesize < 492544
}