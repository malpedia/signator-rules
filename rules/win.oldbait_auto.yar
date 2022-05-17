rule win_oldbait_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.oldbait."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.oldbait"
        malpedia_rule_date = "20220513"
        malpedia_hash = "7f4b2229e6ae614d86d74917f6d5b41890e62a26"
        malpedia_version = "20220516"
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
        $sequence_0 = { ff75f8 6a00 ff15???????? 85c0 7505 }
            // n = 5, score = 400
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7

        $sequence_1 = { 3571281424 42 3bd6 894510 }
            // n = 4, score = 400
            //   3571281424           | xor                 eax, 0x24142871
            //   42                   | inc                 edx
            //   3bd6                 | cmp                 edx, esi
            //   894510               | mov                 dword ptr [ebp + 0x10], eax

        $sequence_2 = { 8b4510 8bca 83f101 83e107 }
            // n = 4, score = 400
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8bca                 | mov                 ecx, edx
            //   83f101               | xor                 ecx, 1
            //   83e107               | and                 ecx, 7

        $sequence_3 = { 837d1c00 7627 8bc6 2b4520 3b450c 731d 8a06 }
            // n = 7, score = 400
            //   837d1c00             | cmp                 dword ptr [ebp + 0x1c], 0
            //   7627                 | jbe                 0x29
            //   8bc6                 | mov                 eax, esi
            //   2b4520               | sub                 eax, dword ptr [ebp + 0x20]
            //   3b450c               | cmp                 eax, dword ptr [ebp + 0xc]
            //   731d                 | jae                 0x1f
            //   8a06                 | mov                 al, byte ptr [esi]

        $sequence_4 = { 01459c 8b45c8 8945f8 eb05 }
            // n = 4, score = 400
            //   01459c               | add                 dword ptr [ebp - 0x64], eax
            //   8b45c8               | mov                 eax, dword ptr [ebp - 0x38]
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   eb05                 | jmp                 7

        $sequence_5 = { 0145d8 8bb54cffffff 56 ff55d0 }
            // n = 4, score = 400
            //   0145d8               | add                 dword ptr [ebp - 0x28], eax
            //   8bb54cffffff         | mov                 esi, dword ptr [ebp - 0xb4]
            //   56                   | push                esi
            //   ff55d0               | call                dword ptr [ebp - 0x30]

        $sequence_6 = { 0145d8 33ff 8d837ff61800 803800 }
            // n = 4, score = 400
            //   0145d8               | add                 dword ptr [ebp - 0x28], eax
            //   33ff                 | xor                 edi, edi
            //   8d837ff61800         | lea                 eax, [ebx + 0x18f67f]
            //   803800               | cmp                 byte ptr [eax], 0

        $sequence_7 = { 888800b01800 ebda 8b45fc 0531b11800 }
            // n = 4, score = 400
            //   888800b01800         | mov                 byte ptr [eax + 0x18b000], cl
            //   ebda                 | jmp                 0xffffffdc
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   0531b11800           | add                 eax, 0x18b131

        $sequence_8 = { 8bec 8b450c 56 33d2 }
            // n = 4, score = 400
            // 
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   56                   | push                esi
            //   33d2                 | xor                 edx, edx

        $sequence_9 = { 33d2 57 8b7d08 8d70ff }
            // n = 4, score = 400
            //   33d2                 | xor                 edx, edx
            //   57                   | push                edi
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8d70ff               | lea                 esi, [eax - 1]

        $sequence_10 = { 0145d4 41 c1ea04 75dc }
            // n = 4, score = 400
            //   0145d4               | add                 dword ptr [ebp - 0x2c], eax
            //   41                   | inc                 ecx
            //   c1ea04               | shr                 edx, 4
            //   75dc                 | jne                 0xffffffde

        $sequence_11 = { 0145d8 8b45d8 3b45c8 7cc2 }
            // n = 4, score = 400
            //   0145d8               | add                 dword ptr [ebp - 0x28], eax
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]
            //   3b45c8               | cmp                 eax, dword ptr [ebp - 0x38]
            //   7cc2                 | jl                  0xffffffc4

        $sequence_12 = { 6a03 6a00 6a01 6800000080 ff75f8 ff15???????? }
            // n = 6, score = 400
            //   6a03                 | push                3
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   6800000080           | push                0x80000000
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff15????????         |                     

        $sequence_13 = { 0145d8 8b45f0 ff45ec 0fb64004 }
            // n = 4, score = 400
            //   0145d8               | add                 dword ptr [ebp - 0x28], eax
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   ff45ec               | inc                 dword ptr [ebp - 0x14]
            //   0fb64004             | movzx               eax, byte ptr [eax + 4]

        $sequence_14 = { ff75fc ff55f4 5f 5e 5b }
            // n = 5, score = 400
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff55f4               | call                dword ptr [ebp - 0xc]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_15 = { 0103 01451c 8b06 8bc8 c1e906 }
            // n = 5, score = 400
            //   0103                 | add                 dword ptr [ebx], eax
            //   01451c               | add                 dword ptr [ebp + 0x1c], eax
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8bc8                 | mov                 ecx, eax
            //   c1e906               | shr                 ecx, 6

        $sequence_16 = { 895514 83651407 8bc8 2b4df0 }
            // n = 4, score = 100
            //   895514               | mov                 dword ptr [ebp + 0x14], edx
            //   83651407             | and                 dword ptr [ebp + 0x14], 7
            //   8bc8                 | mov                 ecx, eax
            //   2b4df0               | sub                 ecx, dword ptr [ebp - 0x10]

        $sequence_17 = { ffd6 ffd0 68???????? 53 ffd6 68???????? }
            // n = 6, score = 100
            //   ffd6                 | call                esi
            //   ffd0                 | call                eax
            //   68????????           |                     
            //   53                   | push                ebx
            //   ffd6                 | call                esi
            //   68????????           |                     

        $sequence_18 = { 6880000000 6a03 57 6a03 8d85c0feffff 6800000080 }
            // n = 6, score = 100
            //   6880000000           | push                0x80
            //   6a03                 | push                3
            //   57                   | push                edi
            //   6a03                 | push                3
            //   8d85c0feffff         | lea                 eax, [ebp - 0x140]
            //   6800000080           | push                0x80000000

        $sequence_19 = { f7d1 23ca 8b55e8 83e207 }
            // n = 4, score = 100
            //   f7d1                 | not                 ecx
            //   23ca                 | and                 ecx, edx
            //   8b55e8               | mov                 edx, dword ptr [ebp - 0x18]
            //   83e207               | and                 edx, 7

        $sequence_20 = { 03c1 d3e8 32d8 8d47ff }
            // n = 4, score = 100
            //   03c1                 | add                 eax, ecx
            //   d3e8                 | shr                 eax, cl
            //   32d8                 | xor                 bl, al
            //   8d47ff               | lea                 eax, [edi - 1]

        $sequence_21 = { e8???????? 90 90 90 8d85c0feffff }
            // n = 5, score = 100
            //   e8????????           |                     
            //   90                   | nop                 
            //   90                   | nop                 
            //   90                   | nop                 
            //   8d85c0feffff         | lea                 eax, [ebp - 0x140]

        $sequence_22 = { 8d45f4 50 68???????? ff75f8 ffd6 ffd0 6a01 }
            // n = 7, score = 100
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   68????????           |                     
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ffd6                 | call                esi
            //   ffd0                 | call                eax
            //   6a01                 | push                1

        $sequence_23 = { 8b35???????? 68???????? 50 a3???????? ffd6 68???????? 8945e8 }
            // n = 7, score = 100
            //   8b35????????         |                     
            //   68????????           |                     
            //   50                   | push                eax
            //   a3????????           |                     
            //   ffd6                 | call                esi
            //   68????????           |                     
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax

    condition:
        7 of them and filesize < 172032
}