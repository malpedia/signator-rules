rule win_oldbait_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.oldbait."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.oldbait"
        malpedia_rule_date = "20220405"
        malpedia_hash = "ecd38294bd47d5589be5cd5490dc8bb4804afc2a"
        malpedia_version = ""
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
        $sequence_0 = { 0103 01451c 8b06 8bc8 c1e906 }
            // n = 5, score = 400
            //   0103                 | add                 dword ptr [ebx], eax
            //   01451c               | add                 dword ptr [ebp + 0x1c], eax
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8bc8                 | mov                 ecx, eax
            //   c1e906               | shr                 ecx, 6

        $sequence_1 = { 8a09 888800b01800 ebda 8b45fc 0531b11800 50 }
            // n = 6, score = 400
            //   8a09                 | mov                 cl, byte ptr [ecx]
            //   888800b01800         | mov                 byte ptr [eax + 0x18b000], cl
            //   ebda                 | jmp                 0xffffffdc
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   0531b11800           | add                 eax, 0x18b131
            //   50                   | push                eax

        $sequence_2 = { 8bec 8b450c 56 33d2 }
            // n = 4, score = 400
            //   8bec                 | mov                 ebp, esp
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   56                   | push                esi
            //   33d2                 | xor                 edx, edx

        $sequence_3 = { 0145d8 8bb54cffffff 56 ff55d0 }
            // n = 4, score = 400
            //   0145d8               | add                 dword ptr [ebp - 0x28], eax
            //   8bb54cffffff         | mov                 esi, dword ptr [ebp - 0xb4]
            //   56                   | push                esi
            //   ff55d0               | call                dword ptr [ebp - 0x30]

        $sequence_4 = { 837d1c00 8b4d18 762f 8b5d0c }
            // n = 4, score = 400
            //   837d1c00             | cmp                 dword ptr [ebp + 0x1c], 0
            //   8b4d18               | mov                 ecx, dword ptr [ebp + 0x18]
            //   762f                 | jbe                 0x31
            //   8b5d0c               | mov                 ebx, dword ptr [ebp + 0xc]

        $sequence_5 = { 0145d8 33ff 8d837ff61800 803800 }
            // n = 4, score = 400
            //   0145d8               | add                 dword ptr [ebp - 0x28], eax
            //   33ff                 | xor                 edi, edi
            //   8d837ff61800         | lea                 eax, dword ptr [ebx + 0x18f67f]
            //   803800               | cmp                 byte ptr [eax], 0

        $sequence_6 = { 69c061ea0000 3571281424 42 3bd6 894510 72da 8bc7 }
            // n = 7, score = 400
            // 
            //   3571281424           | xor                 eax, 0x24142871
            //   42                   | inc                 edx
            //   3bd6                 | cmp                 edx, esi
            //   894510               | mov                 dword ptr [ebp + 0x10], eax
            //   72da                 | jb                  0xffffffdc
            //   8bc7                 | mov                 eax, edi

        $sequence_7 = { 8945f4 ff35???????? ff75fc ff55f4 5f 5e 5b }
            // n = 7, score = 400
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   ff35????????         |                     
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff55f4               | call                dword ptr [ebp - 0xc]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_8 = { 8b7d08 8d70ff 85f6 7626 8b4510 8bca 83f101 }
            // n = 7, score = 400
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8d70ff               | lea                 esi, dword ptr [eax - 1]
            //   85f6                 | test                esi, esi
            //   7626                 | jbe                 0x28
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8bca                 | mov                 ecx, edx
            //   83f101               | xor                 ecx, 1

        $sequence_9 = { 6a40 6800300000 68d4fd1900 6a00 }
            // n = 4, score = 400
            //   6a40                 | push                0x40
            //   6800300000           | push                0x3000
            //   68d4fd1900           | push                0x19fdd4
            //   6a00                 | push                0

        $sequence_10 = { 01459c 8b45c8 8945f8 eb05 }
            // n = 4, score = 400
            //   01459c               | add                 dword ptr [ebp - 0x64], eax
            //   8b45c8               | mov                 eax, dword ptr [ebp - 0x38]
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   eb05                 | jmp                 7

        $sequence_11 = { 0145d8 8b45d8 3b45c8 7cc2 }
            // n = 4, score = 400
            //   0145d8               | add                 dword ptr [ebp - 0x28], eax
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]
            //   3b45c8               | cmp                 eax, dword ptr [ebp - 0x38]
            //   7cc2                 | jl                  0xffffffc4

        $sequence_12 = { d3e8 30043a 8b4510 69c061ea0000 3571281424 }
            // n = 5, score = 400
            //   d3e8                 | shr                 eax, cl
            //   30043a               | xor                 byte ptr [edx + edi], al
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   69c061ea0000         | imul                eax, eax, 0xea61
            //   3571281424           | xor                 eax, 0x24142871

        $sequence_13 = { 8b4510 8bca 83f101 83e107 d3e8 30043a }
            // n = 6, score = 400
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8bca                 | mov                 ecx, edx
            //   83f101               | xor                 ecx, 1
            //   83e107               | and                 ecx, 7
            //   d3e8                 | shr                 eax, cl
            //   30043a               | xor                 byte ptr [edx + edi], al

        $sequence_14 = { 0145d8 8b45f0 ff45ec 0fb64004 }
            // n = 4, score = 400
            //   0145d8               | add                 dword ptr [ebp - 0x28], eax
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   ff45ec               | inc                 dword ptr [ebp - 0x14]
            //   0fb64004             | movzx               eax, byte ptr [eax + 4]

        $sequence_15 = { 0145d4 41 c1ea04 75dc }
            // n = 4, score = 400
            //   0145d4               | add                 dword ptr [ebp - 0x2c], eax
            //   41                   | inc                 ecx
            //   c1ea04               | shr                 edx, 4
            //   75dc                 | jne                 0xffffffde

        $sequence_16 = { 8bd8 8d45dc 50 68???????? ff75f8 }
            // n = 5, score = 100
            //   8bd8                 | mov                 ebx, eax
            //   8d45dc               | lea                 eax, dword ptr [ebp - 0x24]
            //   50                   | push                eax
            //   68????????           |                     
            //   ff75f8               | push                dword ptr [ebp - 8]

        $sequence_17 = { 83e007 02d9 8a0430 f6eb 8ad8 }
            // n = 5, score = 100
            //   83e007               | and                 eax, 7
            //   02d9                 | add                 bl, cl
            //   8a0430               | mov                 al, byte ptr [eax + esi]
            //   f6eb                 | imul                bl
            //   8ad8                 | mov                 bl, al

        $sequence_18 = { 40 3b45ec 8945f4 7280 8bc8 }
            // n = 5, score = 100
            //   40                   | inc                 eax
            //   3b45ec               | cmp                 eax, dword ptr [ebp - 0x14]
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   7280                 | jb                  0xffffff82
            //   8bc8                 | mov                 ecx, eax

        $sequence_19 = { 8bec 81ec44020000 53 56 57 8d45f4 }
            // n = 6, score = 100
            //   8bec                 | mov                 ebp, esp
            //   81ec44020000         | sub                 esp, 0x244
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8d45f4               | lea                 eax, dword ptr [ebp - 0xc]

        $sequence_20 = { ff35???????? ffd6 ffd0 8d45ec 50 8d45c4 50 }
            // n = 7, score = 100
            //   ff35????????         |                     
            //   ffd6                 | call                esi
            //   ffd0                 | call                eax
            //   8d45ec               | lea                 eax, dword ptr [ebp - 0x14]
            //   50                   | push                eax
            //   8d45c4               | lea                 eax, dword ptr [ebp - 0x3c]
            //   50                   | push                eax

        $sequence_21 = { 68???????? 50 ff55e8 57 6880000000 6a03 }
            // n = 6, score = 100
            //   68????????           |                     
            //   50                   | push                eax
            //   ff55e8               | call                dword ptr [ebp - 0x18]
            //   57                   | push                edi
            //   6880000000           | push                0x80
            //   6a03                 | push                3

        $sequence_22 = { ff75d4 ff75e0 53 68???????? ff35???????? ffd6 }
            // n = 6, score = 100
            //   ff75d4               | push                dword ptr [ebp - 0x2c]
            //   ff75e0               | push                dword ptr [ebp - 0x20]
            //   53                   | push                ebx
            //   68????????           |                     
            //   ff35????????         |                     
            //   ffd6                 | call                esi

        $sequence_23 = { 301c07 41 47 3b4d10 72c0 5f }
            // n = 6, score = 100
            //   301c07               | xor                 byte ptr [edi + eax], bl
            //   41                   | inc                 ecx
            //   47                   | inc                 edi
            //   3b4d10               | cmp                 ecx, dword ptr [ebp + 0x10]
            //   72c0                 | jb                  0xffffffc2
            //   5f                   | pop                 edi

    condition:
        7 of them and filesize < 172032
}