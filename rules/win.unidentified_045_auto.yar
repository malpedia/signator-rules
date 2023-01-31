rule win_unidentified_045_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.unidentified_045."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_045"
        malpedia_rule_date = "20230124"
        malpedia_hash = "2ee0eebba83dce3d019a90519f2f972c0fcf9686"
        malpedia_version = "20230125"
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
        $sequence_0 = { 83c418 68???????? 56 ff15???????? 5f 5e }
            // n = 6, score = 100
            //   83c418               | add                 esp, 0x18
            //   68????????           |                     
            //   56                   | push                esi
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_1 = { 391d???????? 7512 53 53 53 68???????? }
            // n = 6, score = 100
            //   391d????????         |                     
            //   7512                 | jne                 0x14
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   68????????           |                     

        $sequence_2 = { e8???????? 6a00 57 ff75e8 8bd8 ff75e4 8bf2 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   6a00                 | push                0
            //   57                   | push                edi
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   8bd8                 | mov                 ebx, eax
            //   ff75e4               | push                dword ptr [ebp - 0x1c]
            //   8bf2                 | mov                 esi, edx

        $sequence_3 = { 3bc1 7605 8bc8 894dc0 ff45d4 ebe0 }
            // n = 6, score = 100
            //   3bc1                 | cmp                 eax, ecx
            //   7605                 | jbe                 7
            //   8bc8                 | mov                 ecx, eax
            //   894dc0               | mov                 dword ptr [ebp - 0x40], ecx
            //   ff45d4               | inc                 dword ptr [ebp - 0x2c]
            //   ebe0                 | jmp                 0xffffffe2

        $sequence_4 = { ffd3 8bf0 85f6 75c6 }
            // n = 4, score = 100
            //   ffd3                 | call                ebx
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   75c6                 | jne                 0xffffffc8

        $sequence_5 = { 8bc1 8b703c 03f0 0500040000 894508 8d8ef8000000 3bc8 }
            // n = 7, score = 100
            //   8bc1                 | mov                 eax, ecx
            //   8b703c               | mov                 esi, dword ptr [eax + 0x3c]
            //   03f0                 | add                 esi, eax
            //   0500040000           | add                 eax, 0x400
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   8d8ef8000000         | lea                 ecx, [esi + 0xf8]
            //   3bc8                 | cmp                 ecx, eax

        $sequence_6 = { 53 51 50 ff15???????? 53 8d442430 50 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   51                   | push                ecx
            //   50                   | push                eax
            //   ff15????????         |                     
            //   53                   | push                ebx
            //   8d442430             | lea                 eax, [esp + 0x30]
            //   50                   | push                eax

        $sequence_7 = { 8b0d???????? 8901 8b8534ffffff 8b0d???????? 8901 8b8538ffffff 8b0d???????? }
            // n = 7, score = 100
            //   8b0d????????         |                     
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8b8534ffffff         | mov                 eax, dword ptr [ebp - 0xcc]
            //   8b0d????????         |                     
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8b8538ffffff         | mov                 eax, dword ptr [ebp - 0xc8]
            //   8b0d????????         |                     

    condition:
        7 of them and filesize < 73728
}