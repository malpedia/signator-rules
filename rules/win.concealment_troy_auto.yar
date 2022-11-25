rule win_concealment_troy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.concealment_troy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.concealment_troy"
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
        $sequence_0 = { c744244000000000 ff15???????? 85c0 0f844cffffff 8b542424 }
            // n = 5, score = 100
            //   c744244000000000     | mov                 dword ptr [esp + 0x40], 0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f844cffffff         | je                  0xffffff52
            //   8b542424             | mov                 edx, dword ptr [esp + 0x24]

        $sequence_1 = { 52 e8???????? 8b44242c 50 8d8c2470050000 68???????? }
            // n = 6, score = 100
            //   52                   | push                edx
            //   e8????????           |                     
            //   8b44242c             | mov                 eax, dword ptr [esp + 0x2c]
            //   50                   | push                eax
            //   8d8c2470050000       | lea                 ecx, [esp + 0x570]
            //   68????????           |                     

        $sequence_2 = { 57 8d3c85a0774100 8b07 83e61f c1e606 03c6 }
            // n = 6, score = 100
            //   57                   | push                edi
            //   8d3c85a0774100       | lea                 edi, [eax*4 + 0x4177a0]
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   03c6                 | add                 eax, esi

        $sequence_3 = { 53 51 889c2438010000 e8???????? 83c418 6803010000 8d542420 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   51                   | push                ecx
            //   889c2438010000       | mov                 byte ptr [esp + 0x138], bl
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   6803010000           | push                0x103
            //   8d542420             | lea                 edx, [esp + 0x20]

        $sequence_4 = { e8???????? 56 e8???????? 8b8c2438020000 83c418 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b8c2438020000       | mov                 ecx, dword ptr [esp + 0x238]
            //   83c418               | add                 esp, 0x18

        $sequence_5 = { 8bf0 33db 83c408 3bf3 751a 5f }
            // n = 6, score = 100
            //   8bf0                 | mov                 esi, eax
            //   33db                 | xor                 ebx, ebx
            //   83c408               | add                 esp, 8
            //   3bf3                 | cmp                 esi, ebx
            //   751a                 | jne                 0x1c
            //   5f                   | pop                 edi

        $sequence_6 = { 53 52 889c2434030000 e8???????? 83c40c 8d842428030000 }
            // n = 6, score = 100
            //   53                   | push                ebx
            //   52                   | push                edx
            //   889c2434030000       | mov                 byte ptr [esp + 0x334], bl
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d842428030000       | lea                 eax, [esp + 0x328]

        $sequence_7 = { 5b 8b8c2478130000 33cc e8???????? 81c47c130000 c3 8b542414 }
            // n = 7, score = 100
            //   5b                   | pop                 ebx
            //   8b8c2478130000       | mov                 ecx, dword ptr [esp + 0x1378]
            //   33cc                 | xor                 ecx, esp
            //   e8????????           |                     
            //   81c47c130000         | add                 esp, 0x137c
            //   c3                   | ret                 
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]

        $sequence_8 = { e8???????? 83c410 3b442410 725f }
            // n = 4, score = 100
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   3b442410             | cmp                 eax, dword ptr [esp + 0x10]
            //   725f                 | jb                  0x61

        $sequence_9 = { 85c0 7558 8844241c 8944241d 89442421 88442425 }
            // n = 6, score = 100
            //   85c0                 | test                eax, eax
            //   7558                 | jne                 0x5a
            //   8844241c             | mov                 byte ptr [esp + 0x1c], al
            //   8944241d             | mov                 dword ptr [esp + 0x1d], eax
            //   89442421             | mov                 dword ptr [esp + 0x21], eax
            //   88442425             | mov                 byte ptr [esp + 0x25], al

    condition:
        7 of them and filesize < 229376
}