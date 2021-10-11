rule win_blackmatter_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.blackmatter."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackmatter"
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
        $sequence_0 = { 8b4508 8b480c 0fc9 51 8b4808 0fc9 }
            // n = 6, score = 400
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b480c               | mov                 ecx, dword ptr [eax + 0xc]
            //   0fc9                 | bswap               ecx
            //   51                   | push                ecx
            //   8b4808               | mov                 ecx, dword ptr [eax + 8]
            //   0fc9                 | bswap               ecx

        $sequence_1 = { 51 52 e8???????? b96d4ec641 f7e1 0539300000 25ffffff07 }
            // n = 7, score = 400
            //   51                   | push                ecx
            //   52                   | push                edx
            //   e8????????           |                     
            //   b96d4ec641           | mov                 ecx, 0x41c64e6d
            //   f7e1                 | mul                 ecx
            //   0539300000           | add                 eax, 0x3039
            //   25ffffff07           | and                 eax, 0x7ffffff

        $sequence_2 = { 3bc1 7527 ff75f4 ff75f8 e8???????? }
            // n = 5, score = 400
            //   3bc1                 | cmp                 eax, ecx
            //   7527                 | jne                 0x29
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   e8????????           |                     

        $sequence_3 = { eb02 eb05 49 85c9 75da 5e }
            // n = 6, score = 400
            //   eb02                 | jmp                 4
            //   eb05                 | jmp                 7
            //   49                   | dec                 ecx
            //   85c9                 | test                ecx, ecx
            //   75da                 | jne                 0xffffffdc
            //   5e                   | pop                 esi

        $sequence_4 = { ff75fc ff15???????? 8b45fc e9???????? 83c608 4b }
            // n = 6, score = 400
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff15????????         |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   e9????????           |                     
            //   83c608               | add                 esi, 8
            //   4b                   | dec                 ebx

        $sequence_5 = { ff75ec ff75f8 ff15???????? 85c0 7402 }
            // n = 5, score = 400
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7402                 | je                  4

        $sequence_6 = { ff15???????? 85c0 7575 6a00 ff7510 ff750c ff75f4 }
            // n = 7, score = 400
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7575                 | jne                 0x77
            //   6a00                 | push                0
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff75f4               | push                dword ptr [ebp - 0xc]

        $sequence_7 = { 81ec04010000 53 56 57 c745fc00000000 ff35???????? e8???????? }
            // n = 7, score = 400
            //   81ec04010000         | sub                 esp, 0x104
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   ff35????????         |                     
            //   e8????????           |                     

        $sequence_8 = { 8b7138 8b793c 115030 115834 117038 11783c 8b5140 }
            // n = 7, score = 400
            //   8b7138               | mov                 esi, dword ptr [ecx + 0x38]
            //   8b793c               | mov                 edi, dword ptr [ecx + 0x3c]
            //   115030               | adc                 dword ptr [eax + 0x30], edx
            //   115834               | adc                 dword ptr [eax + 0x34], ebx
            //   117038               | adc                 dword ptr [eax + 0x38], esi
            //   11783c               | adc                 dword ptr [eax + 0x3c], edi
            //   8b5140               | mov                 edx, dword ptr [ecx + 0x40]

        $sequence_9 = { 83f905 7305 5e 5d c20400 ac }
            // n = 6, score = 400
            //   83f905               | cmp                 ecx, 5
            //   7305                 | jae                 7
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   ac                   | lodsb               al, byte ptr [esi]

    condition:
        7 of them and filesize < 194560
}