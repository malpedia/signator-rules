rule win_ariabody_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.ariabody."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ariabody"
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
        $sequence_0 = { 8bec 83ec50 53 57 8bd9 }
            // n = 5, score = 300
            //   8bec                 | mov                 dword ptr [esp + 0x28], ebp
            //   83ec50               | xor                 edi, edi
            //   53                   | dec                 eax
            //   57                   | mov                 dword ptr [esp + 0x30], esi
            //   8bd9                 | inc                 ecx

        $sequence_1 = { 8bf8 893e eb13 8b16 8bcf e8???????? 8906 }
            // n = 7, score = 300
            //   8bf8                 | mov                 ebx, ecx
            //   893e                 | mov                 esi, edx
            //   eb13                 | push                esi
            //   8b16                 | lea                 edx, [ebp - 4]
            //   8bcf                 | add                 edi, ecx
            //   e8????????           |                     
            //   8906                 | sub                 esp, 0x50

        $sequence_2 = { 8bf2 56 8d55fc 03f9 e8???????? }
            // n = 5, score = 300
            //   8bf2                 | mov                 dword ptr [esp + 0x78], 0x2074656e
            //   56                   | mov                 dword ptr [esp + 0x7c], 0x74746553
            //   8d55fc               | mov                 dword ptr [esp + 0x80], 0x73676e69
            //   03f9                 | mov                 dword ptr [esp + 0x84], 0
            //   e8????????           |                     

        $sequence_3 = { 3ac3 7402 32c3 88040a 41 }
            // n = 5, score = 300
            //   3ac3                 | mov                 eax, 4
            //   7402                 | dec                 esp
            //   32c3                 | lea                 ecx, [esp + 0x168]
            //   88040a               | dec                 eax
            //   41                   | mov                 dword ptr [eax + 0x20], 0

        $sequence_4 = { 8bcf 0fb6c0 50 ff75fc e8???????? }
            // n = 5, score = 300
            //   8bcf                 | mov                 dword ptr [ebx], edi
            //   0fb6c0               | mov                 ebp, esp
            //   50                   | sub                 esp, 0x50
            //   ff75fc               | push                ebx
            //   e8????????           |                     

        $sequence_5 = { 56 8d0c30 ffd1 8bc6 }
            // n = 4, score = 300
            //   56                   | mov                 edi, eax
            //   8d0c30               | mov                 dword ptr [esi], edi
            //   ffd1                 | jmp                 0x19
            //   8bc6                 | mov                 edx, dword ptr [esi]

        $sequence_6 = { 8901 33c0 40 5b 5e 5f }
            // n = 6, score = 300
            //   8901                 | mov                 edx, dword ptr [ecx + 0x320]
            //   33c0                 | mov                 dword ptr [eax + 0x20], 8
            //   40                   | dec                 eax
            //   5b                   | lea                 ecx, [esp + 0x620]
            //   5e                   | mov                 ebp, esp
            //   5f                   | sub                 esp, 0x50

        $sequence_7 = { 2bd1 8a01 84c0 7406 3ac3 }
            // n = 5, score = 300
            //   2bd1                 | mov                 dword ptr [esi], edi
            //   8a01                 | jmp                 0x15
            //   84c0                 | mov                 edx, dword ptr [esi]
            //   7406                 | mov                 ecx, edi
            //   3ac3                 | mov                 dword ptr [esi], eax

        $sequence_8 = { c74424706f6e5c49 c74424746e746572 c74424786e657420 c744247c53657474 c7842480000000696e6773 c784248400000000000000 }
            // n = 6, score = 100
            //   c74424706f6e5c49     | push                esi
            //   c74424746e746572     | inc                 ecx
            //   c74424786e657420     | push                edi
            //   c744247c53657474     | push                ebp
            //   c7842480000000696e6773     | dec    eax
            //   c784248400000000000000     | sub    esp, 0x1c0

        $sequence_9 = { 41b804000000 4c8d8c2468010000 48c7402000000000 41ff96d0000000 }
            // n = 4, score = 100
            //   41b804000000         | call                dword ptr [esi + 0x1b8]
            //   4c8d8c2468010000     | inc                 ecx
            //   48c7402000000000     | push                ebp
            //   41ff96d0000000       | inc                 ecx

        $sequence_10 = { e8???????? 488d8c2420060000 e8???????? 85c0 7444 8b8424c4030000 83f801 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488d8c2420060000     | dec                 eax
            //   e8????????           |                     
            //   85c0                 | mov                 esi, eax
            //   7444                 | dec                 eax
            //   8b8424c4030000       | test                esi, esi
            //   83f801               | je                  0xda

        $sequence_11 = { 7657 48896c2428 33ff 4889742430 }
            // n = 4, score = 100
            //   7657                 | dec                 eax
            //   48896c2428           | mov                 ecx, ebp
            //   33ff                 | dec                 eax
            //   4889742430           | lea                 edx, [esp + 0x276]

        $sequence_12 = { ff96b8010000 4889e9 488d942476020000 ff96b8010000 }
            // n = 4, score = 100
            //   ff96b8010000         | xor                 ebx, ebx
            //   4889e9               | inc                 ecx
            //   488d942476020000     | mov                 eax, 0x2000
            //   ff96b8010000         | cmp                 ebp, 0x2000

        $sequence_13 = { 41ff5710 4889c6 4885f6 0f84ce000000 33db 41b800200000 81fd00200000 }
            // n = 7, score = 100
            //   41ff5710             | mov                 dword ptr [esi + 0x28], eax
            //   4889c6               | inc                 ecx
            //   4885f6               | call                dword ptr [edi + 0x120]
            //   0f84ce000000         | test                eax, eax
            //   33db                 | jne                 0x1b8
            //   41b800200000         | inc                 ecx
            //   81fd00200000         | call                dword ptr [edi + 0x10]

        $sequence_14 = { 4c8d8c24ec000000 488d842400010000 4c896e20 48894628 41ff9720010000 85c0 0f85a5010000 }
            // n = 7, score = 100
            //   4c8d8c24ec000000     | dec                 esp
            //   488d842400010000     | lea                 ecx, [esp + 0xec]
            //   4c896e20             | dec                 eax
            //   48894628             | lea                 eax, [esp + 0x100]
            //   41ff9720010000       | dec                 esp
            //   85c0                 | mov                 dword ptr [esi + 0x20], ebp
            //   0f85a5010000         | dec                 eax

        $sequence_15 = { 4155 4156 4157 55 4881ecc0010000 4989d4 4889cd }
            // n = 7, score = 100
            //   4155                 | dec                 eax
            //   4156                 | lea                 ecx, [esp + 0x620]
            //   4157                 | test                eax, eax
            //   55                   | je                  0x48
            //   4881ecc0010000       | mov                 eax, dword ptr [esp + 0x3c4]
            //   4989d4               | cmp                 eax, 1
            //   4889cd               | call                dword ptr [esi + 0x1b8]

    condition:
        7 of them and filesize < 253952
}