rule win_taleret_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.taleret."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.taleret"
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
        $sequence_0 = { ffd6 85c0 7443 8b2d???????? 8b3d???????? 8b1d???????? }
            // n = 6, score = 100
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   7443                 | je                  0x45
            //   8b2d????????         |                     
            //   8b3d????????         |                     
            //   8b1d????????         |                     

        $sequence_1 = { 51 ffd5 3d02010000 752a 8d542410 52 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   ffd5                 | call                ebp
            //   3d02010000           | cmp                 eax, 0x102
            //   752a                 | jne                 0x2c
            //   8d542410             | lea                 edx, dword ptr [esp + 0x10]
            //   52                   | push                edx

        $sequence_2 = { 51 68???????? 52 e8???????? 50 8d4c2414 c644243802 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   68????????           |                     
            //   52                   | push                edx
            //   e8????????           |                     
            //   50                   | push                eax
            //   8d4c2414             | lea                 ecx, dword ptr [esp + 0x14]
            //   c644243802           | mov                 byte ptr [esp + 0x38], 2

        $sequence_3 = { 83c8ff e9???????? 668b4b44 8b4340 51 }
            // n = 5, score = 100
            //   83c8ff               | or                  eax, 0xffffffff
            //   e9????????           |                     
            //   668b4b44             | mov                 cx, word ptr [ebx + 0x44]
            //   8b4340               | mov                 eax, dword ptr [ebx + 0x40]
            //   51                   | push                ecx

        $sequence_4 = { 8b3d???????? 50 ffd7 8b742430 81e6ffff0000 }
            // n = 5, score = 100
            //   8b3d????????         |                     
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   8b742430             | mov                 esi, dword ptr [esp + 0x30]
            //   81e6ffff0000         | and                 esi, 0xffff

        $sequence_5 = { c68424ac0300000e e8???????? 8d4c2428 c68424a80300000d e8???????? 8d4c2430 c68424a80300000c }
            // n = 7, score = 100
            //   c68424ac0300000e     | mov                 byte ptr [esp + 0x3ac], 0xe
            //   e8????????           |                     
            //   8d4c2428             | lea                 ecx, dword ptr [esp + 0x28]
            //   c68424a80300000d     | mov                 byte ptr [esp + 0x3a8], 0xd
            //   e8????????           |                     
            //   8d4c2430             | lea                 ecx, dword ptr [esp + 0x30]
            //   c68424a80300000c     | mov                 byte ptr [esp + 0x3a8], 0xc

        $sequence_6 = { ffd5 8b442414 85c0 0f8592000000 8d4c2410 6a00 }
            // n = 6, score = 100
            //   ffd5                 | call                ebp
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   85c0                 | test                eax, eax
            //   0f8592000000         | jne                 0x98
            //   8d4c2410             | lea                 ecx, dword ptr [esp + 0x10]
            //   6a00                 | push                0

        $sequence_7 = { 8d4c2414 c644242402 e8???????? 8d4c2414 c644242001 e8???????? }
            // n = 6, score = 100
            //   8d4c2414             | lea                 ecx, dword ptr [esp + 0x14]
            //   c644242402           | mov                 byte ptr [esp + 0x24], 2
            //   e8????????           |                     
            //   8d4c2414             | lea                 ecx, dword ptr [esp + 0x14]
            //   c644242001           | mov                 byte ptr [esp + 0x20], 1
            //   e8????????           |                     

        $sequence_8 = { 8b842418080000 83c404 50 ff15???????? 5f 5b 5e }
            // n = 7, score = 100
            //   8b842418080000       | mov                 eax, dword ptr [esp + 0x818]
            //   83c404               | add                 esp, 4
            //   50                   | push                eax
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx
            //   5e                   | pop                 esi

        $sequence_9 = { e8???????? 85c0 7409 ebac 56 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7409                 | je                  0xb
            //   ebac                 | jmp                 0xffffffae
            //   56                   | push                esi

    condition:
        7 of them and filesize < 73728
}