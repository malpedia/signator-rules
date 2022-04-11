rule win_ketrum_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.ketrum."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ketrum"
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
        $sequence_0 = { b9???????? 8995f0cbffff 3bc7 7321 898df0cbffff 898df4cbffff 393d???????? }
            // n = 7, score = 200
            //   b9????????           |                     
            //   8995f0cbffff         | mov                 dword ptr [ebp - 0x3410], edx
            //   3bc7                 | cmp                 eax, edi
            //   7321                 | jae                 0x23
            //   898df0cbffff         | mov                 dword ptr [ebp - 0x3410], ecx
            //   898df4cbffff         | mov                 dword ptr [ebp - 0x340c], ecx
            //   393d????????         |                     

        $sequence_1 = { 8db518f6ffff e8???????? e8???????? 6a10 68???????? }
            // n = 5, score = 200
            //   8db518f6ffff         | lea                 esi, dword ptr [ebp - 0x9e8]
            //   e8????????           |                     
            //   e8????????           |                     
            //   6a10                 | push                0x10
            //   68????????           |                     

        $sequence_2 = { e8???????? c9 c3 55 8bec b828400000 e8???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   c9                   | leave               
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   b828400000           | mov                 eax, 0x4028
            //   e8????????           |                     

        $sequence_3 = { c3 55 8bec b8282c0000 e8???????? a1???????? 33c5 }
            // n = 7, score = 200
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   b8282c0000           | mov                 eax, 0x2c28
            //   e8????????           |                     
            //   a1????????           |                     
            //   33c5                 | xor                 eax, ebp

        $sequence_4 = { 53 50 e8???????? 83c40c e8???????? 833d????????10 }
            // n = 6, score = 200
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   e8????????           |                     
            //   833d????????10       |                     

        $sequence_5 = { 8995f4cbffff ebe3 c785e8cbffff74374200 8b15???????? }
            // n = 4, score = 200
            //   8995f4cbffff         | mov                 dword ptr [ebp - 0x340c], edx
            //   ebe3                 | jmp                 0xffffffe5
            //   c785e8cbffff74374200     | mov    dword ptr [ebp - 0x3418], 0x423774
            //   8b15????????         |                     

        $sequence_6 = { 56 e8???????? c1f805 56 8d3c85a0bc6200 e8???????? 83e01f }
            // n = 7, score = 200
            //   56                   | push                esi
            //   e8????????           |                     
            //   c1f805               | sar                 eax, 5
            //   56                   | push                esi
            //   8d3c85a0bc6200       | lea                 edi, dword ptr [eax*4 + 0x62bca0]
            //   e8????????           |                     
            //   83e01f               | and                 eax, 0x1f

        $sequence_7 = { 57 8d8584faffff 68???????? 50 }
            // n = 4, score = 200
            //   57                   | push                edi
            //   8d8584faffff         | lea                 eax, dword ptr [ebp - 0x57c]
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_8 = { 8d8390000000 89bbb0000000 83781408 c78524efffff01000000 7202 8b00 }
            // n = 6, score = 100
            //   8d8390000000         | lea                 eax, dword ptr [ebx + 0x90]
            //   89bbb0000000         | mov                 dword ptr [ebx + 0xb0], edi
            //   83781408             | cmp                 dword ptr [eax + 0x14], 8
            //   c78524efffff01000000     | mov    dword ptr [ebp - 0x10dc], 1
            //   7202                 | jb                  4
            //   8b00                 | mov                 eax, dword ptr [eax]

        $sequence_9 = { 59 68???????? 8d8d74efffff c68533efffff01 }
            // n = 4, score = 100
            //   59                   | pop                 ecx
            //   68????????           |                     
            //   8d8d74efffff         | lea                 ecx, dword ptr [ebp - 0x108c]
            //   c68533efffff01       | mov                 byte ptr [ebp - 0x10cd], 1

        $sequence_10 = { 0f88b2010000 8bc7 8bce e8???????? 8b4e18 894804 }
            // n = 6, score = 100
            //   0f88b2010000         | js                  0x1b8
            //   8bc7                 | mov                 eax, edi
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   8b4e18               | mov                 ecx, dword ptr [esi + 0x18]
            //   894804               | mov                 dword ptr [eax + 4], ecx

        $sequence_11 = { 55 8bec 8b4508 8bc8 83e01f c1f905 8b0c8d20174800 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8bc8                 | mov                 ecx, eax
            //   83e01f               | and                 eax, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   8b0c8d20174800       | mov                 ecx, dword ptr [ecx*4 + 0x481720]

        $sequence_12 = { 7506 ff15???????? 33c0 c745bc07000000 895db8 }
            // n = 5, score = 100
            //   7506                 | jne                 8
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax
            //   c745bc07000000       | mov                 dword ptr [ebp - 0x44], 7
            //   895db8               | mov                 dword ptr [ebp - 0x48], ebx

        $sequence_13 = { 85c0 7415 8b850cefffff 6aff 6a00 8dbbac010000 }
            // n = 6, score = 100
            //   85c0                 | test                eax, eax
            //   7415                 | je                  0x17
            //   8b850cefffff         | mov                 eax, dword ptr [ebp - 0x10f4]
            //   6aff                 | push                -1
            //   6a00                 | push                0
            //   8dbbac010000         | lea                 edi, dword ptr [ebx + 0x1ac]

        $sequence_14 = { e8???????? 59 ebb0 8b4610 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   ebb0                 | jmp                 0xffffffb2
            //   8b4610               | mov                 eax, dword ptr [esi + 0x10]

        $sequence_15 = { 68???????? 50 ffd6 83c410 6a01 33ff }
            // n = 6, score = 100
            //   68????????           |                     
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   83c410               | add                 esp, 0x10
            //   6a01                 | push                1
            //   33ff                 | xor                 edi, edi

    condition:
        7 of them and filesize < 4599808
}