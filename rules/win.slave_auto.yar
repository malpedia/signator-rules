rule win_slave_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.slave."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.slave"
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
        $sequence_0 = { 33c8 8b45f4 3345ec 23c2 03ce 3345f4 03c1 }
            // n = 7, score = 300
            //   33c8                 | xor                 ecx, eax
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   3345ec               | xor                 eax, dword ptr [ebp - 0x14]
            //   23c2                 | and                 eax, edx
            //   03ce                 | add                 ecx, esi
            //   3345f4               | xor                 eax, dword ptr [ebp - 0xc]
            //   03c1                 | add                 eax, ecx

        $sequence_1 = { 8bcf 53 8b09 894108 8b45f8 034644 }
            // n = 6, score = 300
            //   8bcf                 | mov                 ecx, edi
            //   53                   | push                ebx
            //   8b09                 | mov                 ecx, dword ptr [ecx]
            //   894108               | mov                 dword ptr [ecx + 8], eax
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   034644               | add                 eax, dword ptr [esi + 0x44]

        $sequence_2 = { c786ec02000000000000 808e0603000080 eb0a c786f002000000000000 837df000 0f8449030000 8a9608010000 }
            // n = 7, score = 300
            //   c786ec02000000000000     | mov    dword ptr [esi + 0x2ec], 0
            //   808e0603000080       | or                  byte ptr [esi + 0x306], 0x80
            //   eb0a                 | jmp                 0xc
            //   c786f002000000000000     | mov    dword ptr [esi + 0x2f0], 0
            //   837df000             | cmp                 dword ptr [ebp - 0x10], 0
            //   0f8449030000         | je                  0x34f
            //   8a9608010000         | mov                 dl, byte ptr [esi + 0x108]

        $sequence_3 = { 8b45dc c1c802 33c8 8b45f0 8bd8 03ca 0b5ddc }
            // n = 7, score = 300
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   c1c802               | ror                 eax, 2
            //   33c8                 | xor                 ecx, eax
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8bd8                 | mov                 ebx, eax
            //   03ca                 | add                 ecx, edx
            //   0b5ddc               | or                  ebx, dword ptr [ebp - 0x24]

        $sequence_4 = { 8ac8 80e1f0 80c110 32c8 80e130 32c8 888e07030000 }
            // n = 7, score = 300
            //   8ac8                 | mov                 cl, al
            //   80e1f0               | and                 cl, 0xf0
            //   80c110               | add                 cl, 0x10
            //   32c8                 | xor                 cl, al
            //   80e130               | and                 cl, 0x30
            //   32c8                 | xor                 cl, al
            //   888e07030000         | mov                 byte ptr [esi + 0x307], cl

        $sequence_5 = { 83c704 8906 83c604 8b07 85c0 75d3 8b7dfc }
            // n = 7, score = 300
            //   83c704               | add                 edi, 4
            //   8906                 | mov                 dword ptr [esi], eax
            //   83c604               | add                 esi, 4
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   85c0                 | test                eax, eax
            //   75d3                 | jne                 0xffffffd5
            //   8b7dfc               | mov                 edi, dword ptr [ebp - 4]

        $sequence_6 = { 8b4dfc 8bf8 8b4608 2b4604 8945e4 8939 8d4801 }
            // n = 7, score = 300
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8bf8                 | mov                 edi, eax
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   2b4604               | sub                 eax, dword ptr [esi + 4]
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8939                 | mov                 dword ptr [ecx], edi
            //   8d4801               | lea                 ecx, [eax + 1]

        $sequence_7 = { c1c802 33c8 8b45dc 8bf0 03ca 0b75e0 }
            // n = 6, score = 300
            //   c1c802               | ror                 eax, 2
            //   33c8                 | xor                 ecx, eax
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   8bf0                 | mov                 esi, eax
            //   03ca                 | add                 ecx, edx
            //   0b75e0               | or                  esi, dword ptr [ebp - 0x20]

        $sequence_8 = { ff15???????? 8b5d0c 8d4dfc 83c404 }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   8b5d0c               | mov                 ebx, dword ptr [ebp + 0xc]
            //   8d4dfc               | lea                 ecx, [ebp - 4]
            //   83c404               | add                 esp, 4

        $sequence_9 = { 8b45d8 8bf8 03ca 2345e4 0b7de4 237dd4 }
            // n = 6, score = 300
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]
            //   8bf8                 | mov                 edi, eax
            //   03ca                 | add                 ecx, edx
            //   2345e4               | and                 eax, dword ptr [ebp - 0x1c]
            //   0b7de4               | or                  edi, dword ptr [ebp - 0x1c]
            //   237dd4               | and                 edi, dword ptr [ebp - 0x2c]

    condition:
        7 of them and filesize < 532480
}