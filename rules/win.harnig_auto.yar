rule win_harnig_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.harnig."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.harnig"
        malpedia_rule_date = "20211007"
        malpedia_hash = "e5b790e0f888f252d49063a1251ca60ec2832535"
        malpedia_version = "20211008"
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
        $sequence_0 = { 8b4d08 0fafc9 894d08 ebf2 }
            // n = 4, score = 100
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   0fafc9               | imul                ecx, ecx
            //   894d08               | mov                 dword ptr [ebp + 8], ecx
            //   ebf2                 | jmp                 0xfffffff4

        $sequence_1 = { 8bec 83ec54 57 6a10 59 68c78a3146 }
            // n = 6, score = 100
            //   8bec                 | mov                 ebp, esp
            //   83ec54               | sub                 esp, 0x54
            //   57                   | push                edi
            //   6a10                 | push                0x10
            //   59                   | pop                 ecx
            //   68c78a3146           | push                0x46318ac7

        $sequence_2 = { 8d85b4fcffff 33ff 8945d0 68d34ee485 8d85b8fdffff 6a04 }
            // n = 6, score = 100
            //   8d85b4fcffff         | lea                 eax, dword ptr [ebp - 0x34c]
            //   33ff                 | xor                 edi, edi
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax
            //   68d34ee485           | push                0x85e44ed3
            //   8d85b8fdffff         | lea                 eax, dword ptr [ebp - 0x248]
            //   6a04                 | push                4

        $sequence_3 = { 7406 8d85e0fbffff 50 8d85e0fdffff 50 }
            // n = 5, score = 100
            //   7406                 | je                  8
            //   8d85e0fbffff         | lea                 eax, dword ptr [ebp - 0x420]
            //   50                   | push                eax
            //   8d85e0fdffff         | lea                 eax, dword ptr [ebp - 0x220]
            //   50                   | push                eax

        $sequence_4 = { 33c0 c745ac44000000 8d7db0 6a01 f3ab e8???????? 8d4df0 }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   c745ac44000000       | mov                 dword ptr [ebp - 0x54], 0x44
            //   8d7db0               | lea                 edi, dword ptr [ebp - 0x50]
            //   6a01                 | push                1
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   e8????????           |                     
            //   8d4df0               | lea                 ecx, dword ptr [ebp - 0x10]

        $sequence_5 = { 6685c0 7509 0fb7450c 2b4610 eb4f 8365fc00 53 }
            // n = 7, score = 100
            //   6685c0               | test                ax, ax
            //   7509                 | jne                 0xb
            //   0fb7450c             | movzx               eax, word ptr [ebp + 0xc]
            //   2b4610               | sub                 eax, dword ptr [esi + 0x10]
            //   eb4f                 | jmp                 0x51
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   53                   | push                ebx

        $sequence_6 = { e8???????? 6a04 8d4df8 51 6a02 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   6a04                 | push                4
            //   8d4df8               | lea                 ecx, dword ptr [ebp - 8]
            //   51                   | push                ecx
            //   6a02                 | push                2

        $sequence_7 = { eb0b 68???????? ff15???????? 8bc8 }
            // n = 4, score = 100
            //   eb0b                 | jmp                 0xd
            //   68????????           |                     
            //   ff15????????         |                     
            //   8bc8                 | mov                 ecx, eax

        $sequence_8 = { e8???????? 88041e 46 3b742418 7ceb 80241e00 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   88041e               | mov                 byte ptr [esi + ebx], al
            //   46                   | inc                 esi
            //   3b742418             | cmp                 esi, dword ptr [esp + 0x18]
            //   7ceb                 | jl                  0xffffffed
            //   80241e00             | and                 byte ptr [esi + ebx], 0

        $sequence_9 = { 8d85e0feffff 50 8d85e0fdffff 50 e8???????? 8d85e0feffff 50 }
            // n = 7, score = 100
            //   8d85e0feffff         | lea                 eax, dword ptr [ebp - 0x120]
            //   50                   | push                eax
            //   8d85e0fdffff         | lea                 eax, dword ptr [ebp - 0x220]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d85e0feffff         | lea                 eax, dword ptr [ebp - 0x120]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 49152
}