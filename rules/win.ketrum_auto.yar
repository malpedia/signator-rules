rule win_ketrum_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.ketrum."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ketrum"
        malpedia_rule_date = "20221118"
        malpedia_hash = "e0702e2e6d1d00da65c8a29a4ebacd0a4c59e1af"
        malpedia_version = "20221125"
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
        $sequence_0 = { 56 8d8578fcffff 53 50 e8???????? 83c40c 8d8534fbffff }
            // n = 7, score = 200
            //   56                   | push                esi
            //   8d8578fcffff         | lea                 eax, [ebp - 0x388]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d8534fbffff         | lea                 eax, [ebp - 0x4cc]

        $sequence_1 = { 7321 898df0cbffff 898df4cbffff 393d???????? 7215 }
            // n = 5, score = 200
            //   7321                 | jae                 0x23
            //   898df0cbffff         | mov                 dword ptr [ebp - 0x3410], ecx
            //   898df4cbffff         | mov                 dword ptr [ebp - 0x340c], ecx
            //   393d????????         |                     
            //   7215                 | jb                  0x17

        $sequence_2 = { ff15???????? ffb5f4cbffff e8???????? 8d85fcfbffff }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   ffb5f4cbffff         | push                dword ptr [ebp - 0x340c]
            //   e8????????           |                     
            //   8d85fcfbffff         | lea                 eax, [ebp - 0x404]

        $sequence_3 = { 59 8b0d???????? ba???????? 8bf9 83f810 7302 }
            // n = 6, score = 200
            //   59                   | pop                 ecx
            //   8b0d????????         |                     
            //   ba????????           |                     
            //   8bf9                 | mov                 edi, ecx
            //   83f810               | cmp                 eax, 0x10
            //   7302                 | jae                 4

        $sequence_4 = { 83c202 6685c0 75f4 83bd6cffffff00 6a0c 8bfa }
            // n = 6, score = 200
            //   83c202               | add                 edx, 2
            //   6685c0               | test                ax, ax
            //   75f4                 | jne                 0xfffffff6
            //   83bd6cffffff00       | cmp                 dword ptr [ebp - 0x94], 0
            //   6a0c                 | push                0xc
            //   8bfa                 | mov                 edi, edx

        $sequence_5 = { e8???????? 57 50 e8???????? 8bf8 56 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   57                   | push                edi
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   56                   | push                esi

        $sequence_6 = { b9???????? e8???????? 68???????? 6a07 58 }
            // n = 5, score = 200
            //   b9????????           |                     
            //   e8????????           |                     
            //   68????????           |                     
            //   6a07                 | push                7
            //   58                   | pop                 eax

        $sequence_7 = { ffb5f4bfffff ffb5f8bfffff e8???????? ffb5e4bfffff 8b8df8bfffff ffb5ecbfffff e8???????? }
            // n = 7, score = 200
            //   ffb5f4bfffff         | push                dword ptr [ebp - 0x400c]
            //   ffb5f8bfffff         | push                dword ptr [ebp - 0x4008]
            //   e8????????           |                     
            //   ffb5e4bfffff         | push                dword ptr [ebp - 0x401c]
            //   8b8df8bfffff         | mov                 ecx, dword ptr [ebp - 0x4008]
            //   ffb5ecbfffff         | push                dword ptr [ebp - 0x4014]
            //   e8????????           |                     

        $sequence_8 = { 8d8558f9ffff 50 53 53 53 }
            // n = 5, score = 100
            //   8d8558f9ffff         | lea                 eax, [ebp - 0x6a8]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   53                   | push                ebx

        $sequence_9 = { c70009000000 e8???????? ebda 8bc3 c1f805 8d3c8520174800 }
            // n = 6, score = 100
            //   c70009000000         | mov                 dword ptr [eax], 9
            //   e8????????           |                     
            //   ebda                 | jmp                 0xffffffdc
            //   8bc3                 | mov                 eax, ebx
            //   c1f805               | sar                 eax, 5
            //   8d3c8520174800       | lea                 edi, [eax*4 + 0x481720]

        $sequence_10 = { 53 8bce e8???????? 50 8bcb e8???????? 83c40c }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   50                   | push                eax
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_11 = { 6683f85d 7460 8b4508 8d7dfc 8d750c e8???????? 85c0 }
            // n = 7, score = 100
            //   6683f85d             | cmp                 ax, 0x5d
            //   7460                 | je                  0x62
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8d7dfc               | lea                 edi, [ebp - 4]
            //   8d750c               | lea                 esi, [ebp + 0xc]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_12 = { 33db ff75c4 e8???????? 59 }
            // n = 4, score = 100
            //   33db                 | xor                 ebx, ebx
            //   ff75c4               | push                dword ptr [ebp - 0x3c]
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_13 = { 57 53 e8???????? 84c0 7504 }
            // n = 5, score = 100
            //   57                   | push                edi
            //   53                   | push                ebx
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7504                 | jne                 6

        $sequence_14 = { 399d50ffffff 7558 68???????? 8d759c }
            // n = 4, score = 100
            //   399d50ffffff         | cmp                 dword ptr [ebp - 0xb0], ebx
            //   7558                 | jne                 0x5a
            //   68????????           |                     
            //   8d759c               | lea                 esi, [ebp - 0x64]

        $sequence_15 = { 881e e8???????? 83ec1c 8bcc 89a56cfeffff c645fc03 }
            // n = 6, score = 100
            //   881e                 | mov                 byte ptr [esi], bl
            //   e8????????           |                     
            //   83ec1c               | sub                 esp, 0x1c
            //   8bcc                 | mov                 ecx, esp
            //   89a56cfeffff         | mov                 dword ptr [ebp - 0x194], esp
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3

    condition:
        7 of them and filesize < 4599808
}