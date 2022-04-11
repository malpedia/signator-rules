rule win_mars_stealer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.mars_stealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mars_stealer"
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
        $sequence_0 = { 51 ff15???????? 83c40c 6a00 6800004006 6a00 e8???????? }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   83c40c               | add                 esp, 0xc
            //   6a00                 | push                0
            //   6800004006           | push                0x6400000
            //   6a00                 | push                0
            //   e8????????           |                     

        $sequence_1 = { 8b450c 0fb70cc5ba664100 8b5508 898a98af0600 8b450c 0fb70cc5b8664100 8b5508 }
            // n = 7, score = 100
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   0fb70cc5ba664100     | movzx               ecx, word ptr [eax*8 + 0x4166ba]
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   898a98af0600         | mov                 dword ptr [edx + 0x6af98], ecx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   0fb70cc5b8664100     | movzx               ecx, word ptr [eax*8 + 0x4166b8]
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]

        $sequence_2 = { 50 8d8ddcfdffff 51 ff15???????? 85c0 0f85e1000000 8d95a0fbffff }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d8ddcfdffff         | lea                 ecx, dword ptr [ebp - 0x224]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f85e1000000         | jne                 0xe7
            //   8d95a0fbffff         | lea                 edx, dword ptr [ebp - 0x460]

        $sequence_3 = { 83c40c 50 8d8de8feffff 51 }
            // n = 4, score = 100
            //   83c40c               | add                 esp, 0xc
            //   50                   | push                eax
            //   8d8de8feffff         | lea                 ecx, dword ptr [ebp - 0x118]
            //   51                   | push                ecx

        $sequence_4 = { 8b55f4 52 8b45fc 50 8d8de0fdffff }
            // n = 5, score = 100
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   52                   | push                edx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax
            //   8d8de0fdffff         | lea                 ecx, dword ptr [ebp - 0x220]

        $sequence_5 = { 837df820 0f8d61030000 6804010000 8d8de8feffff 51 }
            // n = 5, score = 100
            //   837df820             | cmp                 dword ptr [ebp - 8], 0x20
            //   0f8d61030000         | jge                 0x367
            //   6804010000           | push                0x104
            //   8d8de8feffff         | lea                 ecx, dword ptr [ebp - 0x118]
            //   51                   | push                ecx

        $sequence_6 = { 51 68???????? e8???????? 83c418 8d55fc 52 8d45f8 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   68????????           |                     
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   8d55fc               | lea                 edx, dword ptr [ebp - 4]
            //   52                   | push                edx
            //   8d45f8               | lea                 eax, dword ptr [ebp - 8]

        $sequence_7 = { ff15???????? 50 e8???????? 83c404 50 8b55fc }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   50                   | push                eax
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]

        $sequence_8 = { 8d8d78ecffff 51 e8???????? 8d95e4d7ffff 52 8d85e0d7ffff 50 }
            // n = 7, score = 100
            //   8d8d78ecffff         | lea                 ecx, dword ptr [ebp - 0x1388]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8d95e4d7ffff         | lea                 edx, dword ptr [ebp - 0x281c]
            //   52                   | push                edx
            //   8d85e0d7ffff         | lea                 eax, dword ptr [ebp - 0x2820]
            //   50                   | push                eax

        $sequence_9 = { 83c201 8955f8 8b45f4 8b0c85f0654100 83e907 }
            // n = 5, score = 100
            //   83c201               | add                 edx, 1
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8b0c85f0654100       | mov                 ecx, dword ptr [eax*4 + 0x4165f0]
            //   83e907               | sub                 ecx, 7

    condition:
        7 of them and filesize < 219136
}