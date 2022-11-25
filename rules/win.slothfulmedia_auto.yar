rule win_slothfulmedia_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.slothfulmedia."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.slothfulmedia"
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
        $sequence_0 = { ffd7 59 8945f4 8b7df4 }
            // n = 4, score = 200
            //   ffd7                 | call                edi
            //   59                   | pop                 ecx
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b7df4               | mov                 edi, dword ptr [ebp - 0xc]

        $sequence_1 = { 8b4e10 8d5638 53 e8???????? e9???????? c7834002000080000000 }
            // n = 6, score = 200
            //   8b4e10               | mov                 ecx, dword ptr [esi + 0x10]
            //   8d5638               | lea                 edx, [esi + 0x38]
            //   53                   | push                ebx
            //   e8????????           |                     
            //   e9????????           |                     
            //   c7834002000080000000     | mov    dword ptr [ebx + 0x240], 0x80

        $sequence_2 = { ff75f0 e8???????? 84c0 0f84f9000000 ff7324 }
            // n = 5, score = 200
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   0f84f9000000         | je                  0xff
            //   ff7324               | push                dword ptr [ebx + 0x24]

        $sequence_3 = { bf1c010000 57 8d85e4feffff 6a00 50 e8???????? }
            // n = 6, score = 200
            //   bf1c010000           | mov                 edi, 0x11c
            //   57                   | push                edi
            //   8d85e4feffff         | lea                 eax, [ebp - 0x11c]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_4 = { 6a03 6a00 6a01 6800000010 ff7508 ff15???????? 83f8ff }
            // n = 7, score = 200
            //   6a03                 | push                3
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   6800000010           | push                0x10000000
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   83f8ff               | cmp                 eax, -1

        $sequence_5 = { 0f83bf010000 8b8bf0040000 034df0 6a0c 894dcc 8d4dc8 }
            // n = 6, score = 200
            //   0f83bf010000         | jae                 0x1c5
            //   8b8bf0040000         | mov                 ecx, dword ptr [ebx + 0x4f0]
            //   034df0               | add                 ecx, dword ptr [ebp - 0x10]
            //   6a0c                 | push                0xc
            //   894dcc               | mov                 dword ptr [ebp - 0x34], ecx
            //   8d4dc8               | lea                 ecx, [ebp - 0x38]

        $sequence_6 = { e8???????? cc 55 8bec 05f8040000 50 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   cc                   | int3                
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   05f8040000           | add                 eax, 0x4f8
            //   50                   | push                eax

        $sequence_7 = { 817b0cba3d7a6b 59 59 7438 ff75fc }
            // n = 5, score = 200
            //   817b0cba3d7a6b       | cmp                 dword ptr [ebx + 0xc], 0x6b7a3dba
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   7438                 | je                  0x3a
            //   ff75fc               | push                dword ptr [ebp - 4]

        $sequence_8 = { 74ee 6804010000 8d54240c 6a00 }
            // n = 4, score = 100
            //   74ee                 | je                  0xfffffff0
            //   6804010000           | push                0x104
            //   8d54240c             | lea                 edx, [esp + 0xc]
            //   6a00                 | push                0

        $sequence_9 = { 5f 5e 33cc 33c0 e8???????? 81c40c020000 c21000 }
            // n = 7, score = 100
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   33cc                 | xor                 ecx, esp
            //   33c0                 | xor                 eax, eax
            //   e8????????           |                     
            //   81c40c020000         | add                 esp, 0x20c
            //   c21000               | ret                 0x10

        $sequence_10 = { 89842408020000 56 57 68d0070000 }
            // n = 4, score = 100
            //   89842408020000       | mov                 dword ptr [esp + 0x208], eax
            //   56                   | push                esi
            //   57                   | push                edi
            //   68d0070000           | push                0x7d0

        $sequence_11 = { 6689442414 e8???????? 83c40c 6a00 }
            // n = 4, score = 100
            //   6689442414           | mov                 word ptr [esp + 0x14], ax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a00                 | push                0

        $sequence_12 = { 6a04 6a00 8d4c2410 51 ff15???????? }
            // n = 5, score = 100
            //   6a04                 | push                4
            //   6a00                 | push                0
            //   8d4c2410             | lea                 ecx, [esp + 0x10]
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_13 = { 83c40c 6a00 ff15???????? 8b35???????? 8b3d???????? }
            // n = 5, score = 100
            //   83c40c               | add                 esp, 0xc
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   8b3d????????         |                     

        $sequence_14 = { 68???????? ffd6 85c0 7507 ffd7 83f805 }
            // n = 6, score = 100
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   7507                 | jne                 9
            //   ffd7                 | call                edi
            //   83f805               | cmp                 eax, 5

    condition:
        7 of them and filesize < 122880
}