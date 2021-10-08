rule win_silon_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.silon."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.silon"
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
        $sequence_0 = { e8???????? 83c408 8b55f8 0395e4feffff 0fb602 85c0 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   0395e4feffff         | add                 edx, dword ptr [ebp - 0x11c]
            //   0fb602               | movzx               eax, byte ptr [edx]
            //   85c0                 | test                eax, eax

        $sequence_1 = { 50 e8???????? 83c40c 8985c4fdffff 6a01 68???????? 8b8dc4fdffff }
            // n = 7, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8985c4fdffff         | mov                 dword ptr [ebp - 0x23c], eax
            //   6a01                 | push                1
            //   68????????           |                     
            //   8b8dc4fdffff         | mov                 ecx, dword ptr [ebp - 0x23c]

        $sequence_2 = { 8b1481 8b4208 50 68???????? 8d8d68fdffff 51 ff15???????? }
            // n = 7, score = 200
            //   8b1481               | mov                 edx, dword ptr [ecx + eax*4]
            //   8b4208               | mov                 eax, dword ptr [edx + 8]
            //   50                   | push                eax
            //   68????????           |                     
            //   8d8d68fdffff         | lea                 ecx, dword ptr [ebp - 0x298]
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_3 = { 8b8d04efffff 83c110 51 e8???????? 83c40c 89858ceeffff 83bd8ceeffff00 }
            // n = 7, score = 200
            //   8b8d04efffff         | mov                 ecx, dword ptr [ebp - 0x10fc]
            //   83c110               | add                 ecx, 0x10
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   89858ceeffff         | mov                 dword ptr [ebp - 0x1174], eax
            //   83bd8ceeffff00       | cmp                 dword ptr [ebp - 0x1174], 0

        $sequence_4 = { 8d9588efffff 52 e8???????? 83c404 c6840586efffff00 8b8504efffff 8b4810 }
            // n = 7, score = 200
            //   8d9588efffff         | lea                 edx, dword ptr [ebp - 0x1078]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   c6840586efffff00     | mov                 byte ptr [ebp + eax - 0x107a], 0
            //   8b8504efffff         | mov                 eax, dword ptr [ebp - 0x10fc]
            //   8b4810               | mov                 ecx, dword ptr [eax + 0x10]

        $sequence_5 = { 8b4d08 034df4 0fbe5102 83fa5f 7544 8b4508 0345f4 }
            // n = 7, score = 200
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   034df4               | add                 ecx, dword ptr [ebp - 0xc]
            //   0fbe5102             | movsx               edx, byte ptr [ecx + 2]
            //   83fa5f               | cmp                 edx, 0x5f
            //   7544                 | jne                 0x46
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   0345f4               | add                 eax, dword ptr [ebp - 0xc]

        $sequence_6 = { 83fa31 0f85a6000000 c7458401000000 8d8560fdffff 50 e8???????? }
            // n = 6, score = 200
            //   83fa31               | cmp                 edx, 0x31
            //   0f85a6000000         | jne                 0xac
            //   c7458401000000       | mov                 dword ptr [ebp - 0x7c], 1
            //   8d8560fdffff         | lea                 eax, dword ptr [ebp - 0x2a0]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_7 = { 668b5102 52 e8???????? 83c404 0fb7c0 83f815 0f85b9010000 }
            // n = 7, score = 200
            //   668b5102             | mov                 dx, word ptr [ecx + 2]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   0fb7c0               | movzx               eax, ax
            //   83f815               | cmp                 eax, 0x15
            //   0f85b9010000         | jne                 0x1bf

        $sequence_8 = { d7 830010 fa 830010 098400108c8400 10d8 8400 }
            // n = 7, score = 200
            //   d7                   | xlatb               
            //   830010               | add                 dword ptr [eax], 0x10
            //   fa                   | cli                 
            //   830010               | add                 dword ptr [eax], 0x10
            //   098400108c8400       | or                  dword ptr [eax + eax + 0x848c10], eax
            //   10d8                 | adc                 al, bl
            //   8400                 | test                byte ptr [eax], al

        $sequence_9 = { 52 e8???????? 83c40c 8985c4eeffff }
            // n = 4, score = 200
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8985c4eeffff         | mov                 dword ptr [ebp - 0x113c], eax

    condition:
        7 of them and filesize < 122880
}