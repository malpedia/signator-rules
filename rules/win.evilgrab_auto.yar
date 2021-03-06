rule win_evilgrab_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.evilgrab."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.evilgrab"
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
        $sequence_0 = { 68???????? e9???????? 6a01 68???????? e9???????? 85f6 6a01 }
            // n = 7, score = 200
            //   68????????           |                     
            //   e9????????           |                     
            //   6a01                 | push                1
            //   68????????           |                     
            //   e9????????           |                     
            //   85f6                 | test                esi, esi
            //   6a01                 | push                1

        $sequence_1 = { 8b54243e 8b44243c 81e1ffff0000 81e2ffff0000 51 8b4c243e 25ffff0000 }
            // n = 7, score = 200
            //   8b54243e             | mov                 edx, dword ptr [esp + 0x3e]
            //   8b44243c             | mov                 eax, dword ptr [esp + 0x3c]
            //   81e1ffff0000         | and                 ecx, 0xffff
            //   81e2ffff0000         | and                 edx, 0xffff
            //   51                   | push                ecx
            //   8b4c243e             | mov                 ecx, dword ptr [esp + 0x3e]
            //   25ffff0000           | and                 eax, 0xffff

        $sequence_2 = { 83f8ff 7411 eb08 8b431c 83f8ff 7407 50 }
            // n = 7, score = 200
            //   83f8ff               | cmp                 eax, -1
            //   7411                 | je                  0x13
            //   eb08                 | jmp                 0xa
            //   8b431c               | mov                 eax, dword ptr [ebx + 0x1c]
            //   83f8ff               | cmp                 eax, -1
            //   7407                 | je                  9
            //   50                   | push                eax

        $sequence_3 = { 32db e8???????? 84c0 7405 5e b001 5b }
            // n = 7, score = 200
            //   32db                 | xor                 bl, bl
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7405                 | je                  7
            //   5e                   | pop                 esi
            //   b001                 | mov                 al, 1
            //   5b                   | pop                 ebx

        $sequence_4 = { 33c0 f2ae 8b1d???????? f7d1 49 51 8d4c2438 }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   8b1d????????         |                     
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx
            //   51                   | push                ecx
            //   8d4c2438             | lea                 ecx, [esp + 0x38]

        $sequence_5 = { 742e e8???????? 85c0 7508 56 8bcf e8???????? }
            // n = 7, score = 200
            //   742e                 | je                  0x30
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7508                 | jne                 0xa
            //   56                   | push                esi
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     

        $sequence_6 = { 8d542434 57 52 57 50 8bf0 }
            // n = 6, score = 200
            //   8d542434             | lea                 edx, [esp + 0x34]
            //   57                   | push                edi
            //   52                   | push                edx
            //   57                   | push                edi
            //   50                   | push                eax
            //   8bf0                 | mov                 esi, eax

        $sequence_7 = { 51 68???????? ffd3 bf???????? 83c9ff 33c0 8d542414 }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   68????????           |                     
            //   ffd3                 | call                ebx
            //   bf????????           |                     
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   8d542414             | lea                 edx, [esp + 0x14]

        $sequence_8 = { 8d7c2438 83c9ff 33c0 83c404 8913 f2ae f7d1 }
            // n = 7, score = 200
            //   8d7c2438             | lea                 edi, [esp + 0x38]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   83c404               | add                 esp, 4
            //   8913                 | mov                 dword ptr [ebx], edx
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx

        $sequence_9 = { 6800110000 ff15???????? c685ecefffffae 8b85b0efffff 50 68???????? }
            // n = 6, score = 200
            //   6800110000           | push                0x1100
            //   ff15????????         |                     
            //   c685ecefffffae       | mov                 byte ptr [ebp - 0x1014], 0xae
            //   8b85b0efffff         | mov                 eax, dword ptr [ebp - 0x1050]
            //   50                   | push                eax
            //   68????????           |                     

    condition:
        7 of them and filesize < 327680
}