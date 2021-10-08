rule win_cryptoluck_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.cryptoluck."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cryptoluck"
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
        $sequence_0 = { e8???????? 06 8b00 f8 396c2410 7e26 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   06                   | push                es
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   f8                   | clc                 
            //   396c2410             | cmp                 dword ptr [esp + 0x10], ebp
            //   7e26                 | jle                 0x28

        $sequence_1 = { 0305???????? a3???????? 8b95c8fdffff 899578fdffff 8b8578fdffff 50 }
            // n = 6, score = 100
            //   0305????????         |                     
            //   a3????????           |                     
            //   8b95c8fdffff         | mov                 edx, dword ptr [ebp - 0x238]
            //   899578fdffff         | mov                 dword ptr [ebp - 0x288], edx
            //   8b8578fdffff         | mov                 eax, dword ptr [ebp - 0x288]
            //   50                   | push                eax

        $sequence_2 = { 837df000 7622 8b45fc 83e001 7410 }
            // n = 5, score = 100
            //   837df000             | cmp                 dword ptr [ebp - 0x10], 0
            //   7622                 | jbe                 0x24
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   83e001               | and                 eax, 1
            //   7410                 | je                  0x12

        $sequence_3 = { c785c4faffff34040000 8d8df8faffff 898dc8faffff 83bdc4faffff00 7429 8b95c8faffff c60200 }
            // n = 7, score = 100
            //   c785c4faffff34040000     | mov    dword ptr [ebp - 0x53c], 0x434
            //   8d8df8faffff         | lea                 ecx, dword ptr [ebp - 0x508]
            //   898dc8faffff         | mov                 dword ptr [ebp - 0x538], ecx
            //   83bdc4faffff00       | cmp                 dword ptr [ebp - 0x53c], 0
            //   7429                 | je                  0x2b
            //   8b95c8faffff         | mov                 edx, dword ptr [ebp - 0x538]
            //   c60200               | mov                 byte ptr [edx], 0

        $sequence_4 = { 20b87c002414 00598b f8 7614 3b7016 30bc433001b449 d08bbf04bb40 }
            // n = 7, score = 100
            //   20b87c002414         | and                 byte ptr [eax + 0x1424007c], bh
            //   00598b               | add                 byte ptr [ecx - 0x75], bl
            //   f8                   | clc                 
            //   7614                 | jbe                 0x16
            //   3b7016               | cmp                 esi, dword ptr [eax + 0x16]
            //   30bc433001b449       | xor                 byte ptr [ebx + eax*2 + 0x49b40130], bh
            //   d08bbf04bb40         | ror                 byte ptr [ebx + 0x40bb04bf], 1

        $sequence_5 = { 83c404 8945fc 8b4de0 83c101 894dd0 }
            // n = 5, score = 100
            //   83c404               | add                 esp, 4
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   83c101               | add                 ecx, 1
            //   894dd0               | mov                 dword ptr [ebp - 0x30], ecx

        $sequence_6 = { 83bdd0feffff00 7429 8b8dd4feffff c60100 }
            // n = 4, score = 100
            //   83bdd0feffff00       | cmp                 dword ptr [ebp - 0x130], 0
            //   7429                 | je                  0x2b
            //   8b8dd4feffff         | mov                 ecx, dword ptr [ebp - 0x12c]
            //   c60100               | mov                 byte ptr [ecx], 0

        $sequence_7 = { 50 6a0c ff15???????? 50 ff15???????? 89853cffffff 83bd3cffffff00 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   6a0c                 | push                0xc
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   89853cffffff         | mov                 dword ptr [ebp - 0xc4], eax
            //   83bd3cffffff00       | cmp                 dword ptr [ebp - 0xc4], 0

        $sequence_8 = { 51 0135???????? 3023 85ff 7450 a0???????? 22dd }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   0135????????         |                     
            //   3023                 | xor                 byte ptr [ebx], ah
            //   85ff                 | test                edi, edi
            //   7450                 | je                  0x52
            //   a0????????           |                     
            //   22dd                 | and                 bl, ch

        $sequence_9 = { 8b9538efffff 83c201 899538efffff 8b8530efffff 83e801 898530efffff }
            // n = 6, score = 100
            //   8b9538efffff         | mov                 edx, dword ptr [ebp - 0x10c8]
            //   83c201               | add                 edx, 1
            //   899538efffff         | mov                 dword ptr [ebp - 0x10c8], edx
            //   8b8530efffff         | mov                 eax, dword ptr [ebp - 0x10d0]
            //   83e801               | sub                 eax, 1
            //   898530efffff         | mov                 dword ptr [ebp - 0x10d0], eax

    condition:
        7 of them and filesize < 229376
}