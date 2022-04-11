rule win_vigilant_cleaner_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.vigilant_cleaner."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vigilant_cleaner"
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
        $sequence_0 = { e8???????? cc c20000 b8???????? c3 e8???????? }
            // n = 6, score = 200
            //   e8????????           |                     
            //   cc                   | int3                
            //   c20000               | ret                 0
            //   b8????????           |                     
            //   c3                   | ret                 
            //   e8????????           |                     

        $sequence_1 = { ba58560000 ed 5b 59 5a }
            // n = 5, score = 200
            //   ba58560000           | mov                 edx, 0x5658
            //   ed                   | in                  eax, dx
            //   5b                   | pop                 ebx
            //   59                   | pop                 ecx
            //   5a                   | pop                 edx

        $sequence_2 = { ed 5b 59 5a }
            // n = 4, score = 200
            //   ed                   | in                  eax, dx
            //   5b                   | pop                 ebx
            //   59                   | pop                 ecx
            //   5a                   | pop                 edx

        $sequence_3 = { cc c20000 b8???????? c3 e8???????? 8b4804 830824 }
            // n = 7, score = 200
            //   cc                   | int3                
            //   c20000               | ret                 0
            //   b8????????           |                     
            //   c3                   | ret                 
            //   e8????????           |                     
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   830824               | or                  dword ptr [eax], 0x24

        $sequence_4 = { b868584d56 bb00000000 b90a000000 ba58560000 ed 5b }
            // n = 6, score = 200
            //   b868584d56           | mov                 eax, 0x564d5868
            //   bb00000000           | mov                 ebx, 0
            //   b90a000000           | mov                 ecx, 0xa
            //   ba58560000           | mov                 edx, 0x5658
            //   ed                   | in                  eax, dx
            //   5b                   | pop                 ebx

        $sequence_5 = { 6a07 e8???????? cc c20000 b8???????? c3 e8???????? }
            // n = 7, score = 200
            //   6a07                 | push                7
            //   e8????????           |                     
            //   cc                   | int3                
            //   c20000               | ret                 0
            //   b8????????           |                     
            //   c3                   | ret                 
            //   e8????????           |                     

        $sequence_6 = { cc c20000 b8???????? c3 e8???????? }
            // n = 5, score = 200
            //   cc                   | int3                
            //   c20000               | ret                 0
            //   b8????????           |                     
            //   c3                   | ret                 
            //   e8????????           |                     

        $sequence_7 = { c20000 b8???????? c3 e8???????? 8b4804 830824 }
            // n = 6, score = 200
            //   c20000               | ret                 0
            //   b8????????           |                     
            //   c3                   | ret                 
            //   e8????????           |                     
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   830824               | or                  dword ptr [eax], 0x24

        $sequence_8 = { 53 b868584d56 bb00000000 b90a000000 ba58560000 ed 5b }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   b868584d56           | mov                 eax, 0x564d5868
            //   bb00000000           | mov                 ebx, 0
            //   b90a000000           | mov                 ecx, 0xa
            //   ba58560000           | mov                 edx, 0x5658
            //   ed                   | in                  eax, dx
            //   5b                   | pop                 ebx

        $sequence_9 = { ba58560000 ed 5b 59 }
            // n = 4, score = 200
            //   ba58560000           | mov                 edx, 0x5658
            //   ed                   | in                  eax, dx
            //   5b                   | pop                 ebx
            //   59                   | pop                 ecx

    condition:
        7 of them and filesize < 1181696
}