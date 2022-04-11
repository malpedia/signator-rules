rule win_obscene_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.obscene."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.obscene"
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
        $sequence_0 = { 59 68fc501010 8d85ecf6ffff 50 e8???????? 59 59 }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   68fc501010           | push                0x101050fc
            //   8d85ecf6ffff         | lea                 eax, dword ptr [ebp - 0x914]
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx

        $sequence_1 = { 0f84f0000000 68???????? 68???????? e8???????? }
            // n = 4, score = 100
            //   0f84f0000000         | je                  0xf6
            //   68????????           |                     
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_2 = { 59 ff75ee ff15???????? 0fb7c0 83f819 750d }
            // n = 6, score = 100
            //   59                   | pop                 ecx
            //   ff75ee               | push                dword ptr [ebp - 0x12]
            //   ff15????????         |                     
            //   0fb7c0               | movzx               eax, ax
            //   83f819               | cmp                 eax, 0x19
            //   750d                 | jne                 0xf

        $sequence_3 = { 59 8d8500ffffff 50 68e4411010 e8???????? }
            // n = 5, score = 100
            //   59                   | pop                 ecx
            //   8d8500ffffff         | lea                 eax, dword ptr [ebp - 0x100]
            //   50                   | push                eax
            //   68e4411010           | push                0x101041e4
            //   e8????????           |                     

        $sequence_4 = { ffb5eef7ffff ff15???????? 0fb7c0 83f815 0f85cf010000 8b450c 0fbe00 }
            // n = 7, score = 100
            //   ffb5eef7ffff         | push                dword ptr [ebp - 0x812]
            //   ff15????????         |                     
            //   0fb7c0               | movzx               eax, ax
            //   83f815               | cmp                 eax, 0x15
            //   0f85cf010000         | jne                 0x1d5
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   0fbe00               | movsx               eax, byte ptr [eax]

        $sequence_5 = { 59 8bf0 ff75f8 e8???????? 59 }
            // n = 5, score = 100
            //   59                   | pop                 ecx
            //   8bf0                 | mov                 esi, eax
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_6 = { 68???????? e8???????? 59 80a0e240aa0000 }
            // n = 4, score = 100
            //   68????????           |                     
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   80a0e240aa0000       | and                 byte ptr [eax + 0xaa40e2], 0

        $sequence_7 = { 6814100010 e8???????? 59 59 33c0 c9 }
            // n = 6, score = 100
            //   6814100010           | push                0x10001014
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   33c0                 | xor                 eax, eax
            //   c9                   | leave               

        $sequence_8 = { 83f809 7416 8b4508 0fbe00 }
            // n = 4, score = 100
            //   83f809               | cmp                 eax, 9
            //   7416                 | je                  0x18
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   0fbe00               | movsx               eax, byte ptr [eax]

        $sequence_9 = { ff35???????? 6aff ff15???????? 8b45fc c9 c3 }
            // n = 6, score = 100
            //   ff35????????         |                     
            //   6aff                 | push                -1
            //   ff15????????         |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   c9                   | leave               
            //   c3                   | ret                 

    condition:
        7 of them and filesize < 2170880
}