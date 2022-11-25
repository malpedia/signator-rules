rule win_avcrypt_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.avcrypt."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.avcrypt"
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
        $sequence_0 = { 8d55d8 837dec08 8d4dd8 8b45e8 0f4355d8 0f434dd8 33f6 }
            // n = 7, score = 100
            //   8d55d8               | lea                 edx, [ebp - 0x28]
            //   837dec08             | cmp                 dword ptr [ebp - 0x14], 8
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   0f4355d8             | cmovae              edx, dword ptr [ebp - 0x28]
            //   0f434dd8             | cmovae              ecx, dword ptr [ebp - 0x28]
            //   33f6                 | xor                 esi, esi

        $sequence_1 = { ff15???????? 85c0 7907 32c0 e9???????? 8b3d???????? }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7907                 | jns                 9
            //   32c0                 | xor                 al, al
            //   e9????????           |                     
            //   8b3d????????         |                     

        $sequence_2 = { c645fc04 8d45d8 837dec08 51 0f4345d8 8d8dc8feffff }
            // n = 6, score = 100
            //   c645fc04             | mov                 byte ptr [ebp - 4], 4
            //   8d45d8               | lea                 eax, [ebp - 0x28]
            //   837dec08             | cmp                 dword ptr [ebp - 0x14], 8
            //   51                   | push                ecx
            //   0f4345d8             | cmovae              eax, dword ptr [ebp - 0x28]
            //   8d8dc8feffff         | lea                 ecx, [ebp - 0x138]

        $sequence_3 = { ff75d4 ff15???????? 85c0 7410 807ddc00 0f8466ffffff c645eb01 }
            // n = 7, score = 100
            //   ff75d4               | push                dword ptr [ebp - 0x2c]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7410                 | je                  0x12
            //   807ddc00             | cmp                 byte ptr [ebp - 0x24], 0
            //   0f8466ffffff         | je                  0xffffff6c
            //   c645eb01             | mov                 byte ptr [ebp - 0x15], 1

        $sequence_4 = { 57 e8???????? 83ec18 c645fc05 8bcc 68???????? }
            // n = 6, score = 100
            //   57                   | push                edi
            //   e8????????           |                     
            //   83ec18               | sub                 esp, 0x18
            //   c645fc05             | mov                 byte ptr [ebp - 4], 5
            //   8bcc                 | mov                 ecx, esp
            //   68????????           |                     

        $sequence_5 = { 894608 5e c3 55 8bec 56 8d71e8 }
            // n = 7, score = 100
            //   894608               | mov                 dword ptr [esi + 8], eax
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   56                   | push                esi
            //   8d71e8               | lea                 esi, [ecx - 0x18]

        $sequence_6 = { 8945dc 33c0 52 f7d9 895dc8 8d55c4 }
            // n = 6, score = 100
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   33c0                 | xor                 eax, eax
            //   52                   | push                edx
            //   f7d9                 | neg                 ecx
            //   895dc8               | mov                 dword ptr [ebp - 0x38], ebx
            //   8d55c4               | lea                 edx, [ebp - 0x3c]

        $sequence_7 = { 3bc8 5b 0f47d7 85d2 7418 0fb701 663bc3 }
            // n = 7, score = 100
            //   3bc8                 | cmp                 ecx, eax
            //   5b                   | pop                 ebx
            //   0f47d7               | cmova               edx, edi
            //   85d2                 | test                edx, edx
            //   7418                 | je                  0x1a
            //   0fb701               | movzx               eax, word ptr [ecx]
            //   663bc3               | cmp                 ax, bx

        $sequence_8 = { 8b8574ebffff 83e001 0f8412000000 83a574ebfffffe 8d8d78ffffff e9???????? }
            // n = 6, score = 100
            //   8b8574ebffff         | mov                 eax, dword ptr [ebp - 0x148c]
            //   83e001               | and                 eax, 1
            //   0f8412000000         | je                  0x18
            //   83a574ebfffffe       | and                 dword ptr [ebp - 0x148c], 0xfffffffe
            //   8d8d78ffffff         | lea                 ecx, [ebp - 0x88]
            //   e9????????           |                     

        $sequence_9 = { 8b45fc 83c302 40 8945fc 3bc7 75db 8b5df0 }
            // n = 7, score = 100
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   83c302               | add                 ebx, 2
            //   40                   | inc                 eax
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   3bc7                 | cmp                 eax, edi
            //   75db                 | jne                 0xffffffdd
            //   8b5df0               | mov                 ebx, dword ptr [ebp - 0x10]

    condition:
        7 of them and filesize < 6160384
}