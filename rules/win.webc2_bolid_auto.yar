rule win_webc2_bolid_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.webc2_bolid."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_bolid"
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
        $sequence_0 = { b9???????? 6a00 50 51 ff15???????? 8b45a4 }
            // n = 6, score = 100
            //   b9????????           |                     
            //   6a00                 | push                0
            //   50                   | push                eax
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8b45a4               | mov                 eax, dword ptr [ebp - 0x5c]

        $sequence_1 = { 8d4c2478 c644246c00 e8???????? e9???????? e8???????? 8b0d???????? 8d542420 }
            // n = 7, score = 100
            //   8d4c2478             | lea                 ecx, dword ptr [esp + 0x78]
            //   c644246c00           | mov                 byte ptr [esp + 0x6c], 0
            //   e8????????           |                     
            //   e9????????           |                     
            //   e8????????           |                     
            //   8b0d????????         |                     
            //   8d542420             | lea                 edx, dword ptr [esp + 0x20]

        $sequence_2 = { 7465 8a08 0fb6d1 f6820132410004 7403 40 }
            // n = 6, score = 100
            //   7465                 | je                  0x67
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   0fb6d1               | movzx               edx, cl
            //   f6820132410004       | test                byte ptr [edx + 0x413201], 4
            //   7403                 | je                  5
            //   40                   | inc                 eax

        $sequence_3 = { 3b05???????? 735a 8bc8 83e01f c1f905 8b0c8dc01f4100 }
            // n = 6, score = 100
            //   3b05????????         |                     
            //   735a                 | jae                 0x5c
            //   8bc8                 | mov                 ecx, eax
            //   83e01f               | and                 eax, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   8b0c8dc01f4100       | mov                 ecx, dword ptr [ecx*4 + 0x411fc0]

        $sequence_4 = { 85c9 7410 8d4dd0 e8???????? }
            // n = 4, score = 100
            //   85c9                 | test                ecx, ecx
            //   7410                 | je                  0x12
            //   8d4dd0               | lea                 ecx, dword ptr [ebp - 0x30]
            //   e8????????           |                     

        $sequence_5 = { 50 ff5104 33db 6a01 8d4dd0 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   ff5104               | call                dword ptr [ecx + 4]
            //   33db                 | xor                 ebx, ebx
            //   6a01                 | push                1
            //   8d4dd0               | lea                 ecx, dword ptr [ebp - 0x30]

        $sequence_6 = { e8???????? 8b0d???????? c68424fc01000010 51 53 50 8d4c2420 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b0d????????         |                     
            //   c68424fc01000010     | mov                 byte ptr [esp + 0x1fc], 0x10
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   50                   | push                eax
            //   8d4c2420             | lea                 ecx, dword ptr [esp + 0x20]

        $sequence_7 = { 83e103 f3a4 8b4304 896b08 c6042800 8b8c247c060000 5d }
            // n = 7, score = 100
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8b4304               | mov                 eax, dword ptr [ebx + 4]
            //   896b08               | mov                 dword ptr [ebx + 8], ebp
            //   c6042800             | mov                 byte ptr [eax + ebp], 0
            //   8b8c247c060000       | mov                 ecx, dword ptr [esp + 0x67c]
            //   5d                   | pop                 ebp

        $sequence_8 = { 740b 8b4508 8bcf 50 e8???????? 6a00 }
            // n = 6, score = 100
            //   740b                 | je                  0xd
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8bcf                 | mov                 ecx, edi
            //   50                   | push                eax
            //   e8????????           |                     
            //   6a00                 | push                0

        $sequence_9 = { 8b4dbc 85c9 7505 b9???????? }
            // n = 4, score = 100
            //   8b4dbc               | mov                 ecx, dword ptr [ebp - 0x44]
            //   85c9                 | test                ecx, ecx
            //   7505                 | jne                 7
            //   b9????????           |                     

    condition:
        7 of them and filesize < 163840
}