rule win_unidentified_031_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.unidentified_031."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_031"
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
        $sequence_0 = { 8b4dd4 50 8d45d8 51 50 56 ff524c }
            // n = 7, score = 100
            //   8b4dd4               | mov                 ecx, dword ptr [ebp - 0x2c]
            //   50                   | push                eax
            //   8d45d8               | lea                 eax, dword ptr [ebp - 0x28]
            //   51                   | push                ecx
            //   50                   | push                eax
            //   56                   | push                esi
            //   ff524c               | call                dword ptr [edx + 0x4c]

        $sequence_1 = { 6a1c 68???????? 56 50 ff15???????? ba???????? 8d4ddc }
            // n = 7, score = 100
            //   6a1c                 | push                0x1c
            //   68????????           |                     
            //   56                   | push                esi
            //   50                   | push                eax
            //   ff15????????         |                     
            //   ba????????           |                     
            //   8d4ddc               | lea                 ecx, dword ptr [ebp - 0x24]

        $sequence_2 = { 7404 33c0 eb22 8b45fc 33f6 f6401110 740f }
            // n = 7, score = 100
            //   7404                 | je                  6
            //   33c0                 | xor                 eax, eax
            //   eb22                 | jmp                 0x24
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   33f6                 | xor                 esi, esi
            //   f6401110             | test                byte ptr [eax + 0x11], 0x10
            //   740f                 | je                  0x11

        $sequence_3 = { eb0c ff15???????? 8b0d???????? 8b510c bb08000000 8d8ea8000000 8b0402 }
            // n = 7, score = 100
            //   eb0c                 | jmp                 0xe
            //   ff15????????         |                     
            //   8b0d????????         |                     
            //   8b510c               | mov                 edx, dword ptr [ecx + 0xc]
            //   bb08000000           | mov                 ebx, 8
            //   8d8ea8000000         | lea                 ecx, dword ptr [esi + 0xa8]
            //   8b0402               | mov                 eax, dword ptr [edx + eax]

        $sequence_4 = { ff15???????? 59 83c8ff 5e c20800 ff742404 e8???????? }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   59                   | pop                 ecx
            //   83c8ff               | or                  eax, 0xffffffff
            //   5e                   | pop                 esi
            //   c20800               | ret                 8
            //   ff742404             | push                dword ptr [esp + 4]
            //   e8????????           |                     

        $sequence_5 = { c78568fdffff40524000 899d60fdffff 8d8560fdffff 50 8d4d8c 51 8d9520ffffff }
            // n = 7, score = 100
            //   c78568fdffff40524000     | mov    dword ptr [ebp - 0x298], 0x405240
            //   899d60fdffff         | mov                 dword ptr [ebp - 0x2a0], ebx
            //   8d8560fdffff         | lea                 eax, dword ptr [ebp - 0x2a0]
            //   50                   | push                eax
            //   8d4d8c               | lea                 ecx, dword ptr [ebp - 0x74]
            //   51                   | push                ecx
            //   8d9520ffffff         | lea                 edx, dword ptr [ebp - 0xe0]

        $sequence_6 = { 50 ff15???????? 83c41c 8d4de0 ff15???????? e9???????? 66397e68 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c41c               | add                 esp, 0x1c
            //   8d4de0               | lea                 ecx, dword ptr [ebp - 0x20]
            //   ff15????????         |                     
            //   e9????????           |                     
            //   66397e68             | cmp                 word ptr [esi + 0x68], di

        $sequence_7 = { 898d60ffffff 8bd9 890a 8b8d64ffffff 33c0 894a04 898568ffffff }
            // n = 7, score = 100
            //   898d60ffffff         | mov                 dword ptr [ebp - 0xa0], ecx
            //   8bd9                 | mov                 ebx, ecx
            //   890a                 | mov                 dword ptr [edx], ecx
            //   8b8d64ffffff         | mov                 ecx, dword ptr [ebp - 0x9c]
            //   33c0                 | xor                 eax, eax
            //   894a04               | mov                 dword ptr [edx + 4], ecx
            //   898568ffffff         | mov                 dword ptr [ebp - 0x98], eax

        $sequence_8 = { 8bd0 8d4db4 ff15???????? 83fe0a 7206 ff15???????? 8b4d94 }
            // n = 7, score = 100
            //   8bd0                 | mov                 edx, eax
            //   8d4db4               | lea                 ecx, dword ptr [ebp - 0x4c]
            //   ff15????????         |                     
            //   83fe0a               | cmp                 esi, 0xa
            //   7206                 | jb                  8
            //   ff15????????         |                     
            //   8b4d94               | mov                 ecx, dword ptr [ebp - 0x6c]

        $sequence_9 = { 50 64892500000000 81ec24040000 53 56 57 8965ec }
            // n = 7, score = 100
            //   50                   | push                eax
            //   64892500000000       | mov                 dword ptr fs:[0], esp
            //   81ec24040000         | sub                 esp, 0x424
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8965ec               | mov                 dword ptr [ebp - 0x14], esp

    condition:
        7 of them and filesize < 1998848
}