rule win_malumpos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.malumpos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.malumpos"
        malpedia_rule_date = "20211007"
        malpedia_hash = "e5b790e0f888f252d49063a1251ca60ec2832535"
        malpedia_version = "20211008"
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
        $sequence_0 = { 5a 7808 50 7c04 6683c600 58 3500000000 }
            // n = 7, score = 100
            //   5a                   | pop                 edx
            //   7808                 | js                  0xa
            //   50                   | push                eax
            //   7c04                 | jl                  6
            //   6683c600             | add                 si, 0
            //   58                   | pop                 eax
            //   3500000000           | xor                 eax, 0

        $sequence_1 = { 7ced f6c303 7407 33c0 e9???????? 8bcb c1e902 }
            // n = 7, score = 100
            //   7ced                 | jl                  0xffffffef
            //   f6c303               | test                bl, 3
            //   7407                 | je                  9
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   8bcb                 | mov                 ecx, ebx
            //   c1e902               | shr                 ecx, 2

        $sequence_2 = { 7103 83ea00 3c28 57 }
            // n = 4, score = 100
            //   7103                 | jno                 5
            //   83ea00               | sub                 edx, 0
            //   3c28                 | cmp                 al, 0x28
            //   57                   | push                edi

        $sequence_3 = { 85c0 751a a1???????? 663930 }
            // n = 4, score = 100
            //   85c0                 | test                eax, eax
            //   751a                 | jne                 0x1c
            //   a1????????           |                     
            //   663930               | cmp                 word ptr [eax], si

        $sequence_4 = { ff15???????? 8b7624 33c0 f7c600000004 7405 b800020000 f7c600000020 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8b7624               | mov                 esi, dword ptr [esi + 0x24]
            //   33c0                 | xor                 eax, eax
            //   f7c600000004         | test                esi, 0x4000000
            //   7405                 | je                  7
            //   b800020000           | mov                 eax, 0x200
            //   f7c600000020         | test                esi, 0x20000000

        $sequence_5 = { 7c04 66c1c600 5d 81cd00000000 7505 a9832f673b f9 }
            // n = 7, score = 100
            //   7c04                 | jl                  6
            //   66c1c600             | rol                 si, 0
            //   5d                   | pop                 ebp
            //   81cd00000000         | or                  ebp, 0
            //   7505                 | jne                 7
            //   a9832f673b           | test                eax, 0x3b672f83
            //   f9                   | stc                 

        $sequence_6 = { 81f300000000 59 c0c7e0 6683ce00 }
            // n = 4, score = 100
            //   81f300000000         | xor                 ebx, 0
            //   59                   | pop                 ecx
            //   c0c7e0               | rol                 bh, 0xe0
            //   6683ce00             | or                  si, 0

        $sequence_7 = { 50 8bc5 58 90 7405 51 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   8bc5                 | mov                 eax, ebp
            //   58                   | pop                 eax
            //   90                   | nop                 
            //   7405                 | je                  7
            //   51                   | push                ecx

        $sequence_8 = { 7410 8d8500f5feff 50 68???????? ffd7 59 59 }
            // n = 7, score = 100
            //   7410                 | je                  0x12
            //   8d8500f5feff         | lea                 eax, dword ptr [ebp - 0x10b00]
            //   50                   | push                eax
            //   68????????           |                     
            //   ffd7                 | call                edi
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx

        $sequence_9 = { 56 6a95 83c404 5e 59 7806 }
            // n = 6, score = 100
            //   56                   | push                esi
            //   6a95                 | push                -0x6b
            //   83c404               | add                 esp, 4
            //   5e                   | pop                 esi
            //   59                   | pop                 ecx
            //   7806                 | js                  8

    condition:
        7 of them and filesize < 542720
}