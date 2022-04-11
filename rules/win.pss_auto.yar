rule win_pss_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.pss."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pss"
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
        $sequence_0 = { 8d48fe e8???????? e9???????? 83f811 }
            // n = 4, score = 300
            //   8d48fe               | lea                 ecx, dword ptr [eax - 2]
            //   e8????????           |                     
            //   e9????????           |                     
            //   83f811               | cmp                 eax, 0x11

        $sequence_1 = { ff15???????? 83ceff 3bc6 7504 }
            // n = 4, score = 300
            //   ff15????????         |                     
            // 
            //   3bc6                 | cmp                 eax, esi
            //   7504                 | jne                 6

        $sequence_2 = { 7437 ff15???????? 3de5030000 752a }
            // n = 4, score = 300
            //   7437                 | je                  0x39
            //   ff15????????         |                     
            //   3de5030000           | cmp                 eax, 0x3e5
            //   752a                 | jne                 0x2c

        $sequence_3 = { 752a 6aff ff7610 ff15???????? 85c0 }
            // n = 5, score = 200
            //   752a                 | jne                 0x2c
            //   6aff                 | push                -1
            //   ff7610               | push                dword ptr [esi + 0x10]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_4 = { ffd6 8945f4 83f8ff 757b ff15???????? }
            // n = 5, score = 200
            //   ffd6                 | call                esi
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   83f8ff               | cmp                 eax, -1
            //   757b                 | jne                 0x7d
            //   ff15????????         |                     

        $sequence_5 = { 74e8 ff75f0 8b55ec 8b4df4 e8???????? 59 50 }
            // n = 7, score = 200
            //   74e8                 | je                  0xffffffea
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   50                   | push                eax

        $sequence_6 = { 7728 394714 7423 52 }
            // n = 4, score = 200
            //   7728                 | ja                  0x2a
            //   394714               | cmp                 dword ptr [edi + 0x14], eax
            //   7423                 | je                  0x25
            //   52                   | push                edx

        $sequence_7 = { 33c0 6806020000 66898580f7ffff 8d8582f7ffff 56 50 e8???????? }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   6806020000           | push                0x206
            //   66898580f7ffff       | mov                 word ptr [ebp - 0x880], ax
            //   8d8582f7ffff         | lea                 eax, dword ptr [ebp - 0x87e]
            //   56                   | push                esi
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_8 = { e8???????? cc 488d0df3ea0100 e8???????? cc }
            // n = 5, score = 100
            //   e8????????           |                     
            //   cc                   | dec                 eax
            //   488d0df3ea0100       | test                eax, eax
            //   e8????????           |                     
            //   cc                   | int3                

        $sequence_9 = { 488bf2 e8???????? 488d7820 488bd8 66c740180000 4885ff }
            // n = 6, score = 100
            //   488bf2               | dec                 eax
            //   e8????????           |                     
            //   488d7820             | lea                 ecx, dword ptr [0x1eaf3]
            //   488bd8               | int3                
            //   66c740180000         | dec                 eax
            //   4885ff               | mov                 esi, edx

        $sequence_10 = { ff15???????? 488bc8 ff15???????? 488d15a1b50000 488bcb }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   488bc8               | mov                 word ptr [eax + 0x18], 0
            //   ff15????????         |                     
            //   488d15a1b50000       | dec                 eax
            //   488bcb               | test                edi, edi

        $sequence_11 = { 83caff ff15???????? 85c0 7518 488b03 4885c0 }
            // n = 6, score = 100
            //   83caff               | or                  edx, 0xffffffff
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7518                 | jne                 0x1a
            //   488b03               | dec                 eax
            //   4885c0               | mov                 eax, dword ptr [ebx]

        $sequence_12 = { ff15???????? 85c0 0f95c3 8bc3 488b8c24f0020000 }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   85c0                 | dec                 eax
            //   0f95c3               | lea                 edi, dword ptr [eax + 0x20]
            //   8bc3                 | dec                 eax
            //   488b8c24f0020000     | mov                 ebx, eax

    condition:
        7 of them and filesize < 421888
}