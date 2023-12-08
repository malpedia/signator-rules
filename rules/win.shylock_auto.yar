rule win_shylock_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.shylock."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shylock"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
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
        $sequence_0 = { e8???????? 8d8534ffffff 50 b8???????? e8???????? 59 50 }
            // n = 7, score = 500
            //   e8????????           |                     
            //   8d8534ffffff         | lea                 eax, [ebp - 0xcc]
            //   50                   | push                eax
            //   b8????????           |                     
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   50                   | push                eax

        $sequence_1 = { 8db544ffffff e8???????? 8bc6 50 8d45f8 e8???????? ff30 }
            // n = 7, score = 500
            //   8db544ffffff         | lea                 esi, [ebp - 0xbc]
            //   e8????????           |                     
            //   8bc6                 | mov                 eax, esi
            //   50                   | push                eax
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   e8????????           |                     
            //   ff30                 | push                dword ptr [eax]

        $sequence_2 = { c22c00 0fb64001 50 8d45c8 50 8b45d4 8b30 }
            // n = 7, score = 500
            //   c22c00               | ret                 0x2c
            //   0fb64001             | movzx               eax, byte ptr [eax + 1]
            //   50                   | push                eax
            //   8d45c8               | lea                 eax, [ebp - 0x38]
            //   50                   | push                eax
            //   8b45d4               | mov                 eax, dword ptr [ebp - 0x2c]
            //   8b30                 | mov                 esi, dword ptr [eax]

        $sequence_3 = { c745fc04010000 ff75e4 e8???????? 83c410 ff45f8 3d03010000 0f8559ffffff }
            // n = 7, score = 500
            //   c745fc04010000       | mov                 dword ptr [ebp - 4], 0x104
            //   ff75e4               | push                dword ptr [ebp - 0x1c]
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   ff45f8               | inc                 dword ptr [ebp - 8]
            //   3d03010000           | cmp                 eax, 0x103
            //   0f8559ffffff         | jne                 0xffffff5f

        $sequence_4 = { e8???????? 3c01 743b 8d8588feffff 50 b8???????? e8???????? }
            // n = 7, score = 500
            //   e8????????           |                     
            //   3c01                 | cmp                 al, 1
            //   743b                 | je                  0x3d
            //   8d8588feffff         | lea                 eax, [ebp - 0x178]
            //   50                   | push                eax
            //   b8????????           |                     
            //   e8????????           |                     

        $sequence_5 = { 57 8b7d08 8b4d0c 8a4510 fc f2ae 7504 }
            // n = 7, score = 500
            //   57                   | push                edi
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8a4510               | mov                 al, byte ptr [ebp + 0x10]
            //   fc                   | cld                 
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   7504                 | jne                 6

        $sequence_6 = { 8945b0 8d856cffffff 50 8b45fc ff7018 ff9540ffffff 898534ffffff }
            // n = 7, score = 500
            //   8945b0               | mov                 dword ptr [ebp - 0x50], eax
            //   8d856cffffff         | lea                 eax, [ebp - 0x94]
            //   50                   | push                eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   ff7018               | push                dword ptr [eax + 0x18]
            //   ff9540ffffff         | call                dword ptr [ebp - 0xc0]
            //   898534ffffff         | mov                 dword ptr [ebp - 0xcc], eax

        $sequence_7 = { 8d75f8 8bfc e8???????? 8d8504ffffff 50 ff7508 e8???????? }
            // n = 7, score = 500
            //   8d75f8               | lea                 esi, [ebp - 8]
            //   8bfc                 | mov                 edi, esp
            //   e8????????           |                     
            //   8d8504ffffff         | lea                 eax, [ebp - 0xfc]
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     

        $sequence_8 = { 51 33d2 8d5df8 e8???????? 8d45ec e8???????? 8bf8 }
            // n = 7, score = 500
            //   51                   | push                ecx
            //   33d2                 | xor                 edx, edx
            //   8d5df8               | lea                 ebx, [ebp - 8]
            //   e8????????           |                     
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax

        $sequence_9 = { e8???????? e8???????? 59 59 8bf0 e8???????? 8d75fc }
            // n = 7, score = 500
            //   e8????????           |                     
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     
            //   8d75fc               | lea                 esi, [ebp - 4]

    condition:
        7 of them and filesize < 630784
}