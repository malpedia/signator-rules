rule win_mirage_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.mirage."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mirage"
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
        $sequence_0 = { 8bc7 6a02 53 f7d8 50 ff75fc }
            // n = 6, score = 200
            //   8bc7                 | mov                 eax, edi
            //   6a02                 | push                2
            //   53                   | push                ebx
            //   f7d8                 | neg                 eax
            //   50                   | push                eax
            //   ff75fc               | push                dword ptr [ebp - 4]

        $sequence_1 = { 6a09 8d45e8 ffb64c010000 50 e8???????? }
            // n = 5, score = 200
            //   6a09                 | push                9
            //   8d45e8               | lea                 eax, dword ptr [ebp - 0x18]
            //   ffb64c010000         | push                dword ptr [esi + 0x14c]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_2 = { e8???????? 83c414 85ff 7e41 6a00 8d45ff }
            // n = 6, score = 200
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   85ff                 | test                edi, edi
            //   7e41                 | jle                 0x43
            //   6a00                 | push                0
            //   8d45ff               | lea                 eax, dword ptr [ebp - 1]

        $sequence_3 = { 8bec 83ec10 ff7508 ff15???????? 85c0 741f 0fbf480a }
            // n = 7, score = 200
            //   8bec                 | mov                 ebp, esp
            //   83ec10               | sub                 esp, 0x10
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   741f                 | je                  0x21
            //   0fbf480a             | movsx               ecx, word ptr [eax + 0xa]

        $sequence_4 = { b9???????? 50 e8???????? 56 894510 ff7514 57 }
            // n = 7, score = 200
            //   b9????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   56                   | push                esi
            //   894510               | mov                 dword ptr [ebp + 0x10], eax
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   57                   | push                edi

        $sequence_5 = { 8d45f4 50 53 68???????? c745f804010000 }
            // n = 5, score = 200
            //   8d45f4               | lea                 eax, dword ptr [ebp - 0xc]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   68????????           |                     
            //   c745f804010000       | mov                 dword ptr [ebp - 8], 0x104

        $sequence_6 = { 68???????? c745f804010000 ff75fc ff15???????? ff75fc }
            // n = 5, score = 200
            //   68????????           |                     
            //   c745f804010000       | mov                 dword ptr [ebp - 8], 0x104
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff15????????         |                     
            //   ff75fc               | push                dword ptr [ebp - 4]

        $sequence_7 = { 68???????? 6801000080 ff15???????? 85c0 7556 }
            // n = 5, score = 200
            //   68????????           |                     
            //   6801000080           | push                0x80000001
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7556                 | jne                 0x58

        $sequence_8 = { 83c005 ebda 83bd54ffffff01 750e 33c0 807de601 }
            // n = 6, score = 200
            //   83c005               | add                 eax, 5
            //   ebda                 | jmp                 0xffffffdc
            //   83bd54ffffff01       | cmp                 dword ptr [ebp - 0xac], 1
            //   750e                 | jne                 0x10
            //   33c0                 | xor                 eax, eax
            //   807de601             | cmp                 byte ptr [ebp - 0x1a], 1

        $sequence_9 = { f3a5 8d8dd0fcffff e8???????? 834dfcff 8d8dd0fcffff e8???????? }
            // n = 6, score = 200
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8d8dd0fcffff         | lea                 ecx, dword ptr [ebp - 0x330]
            //   e8????????           |                     
            //   834dfcff             | or                  dword ptr [ebp - 4], 0xffffffff
            //   8d8dd0fcffff         | lea                 ecx, dword ptr [ebp - 0x330]
            //   e8????????           |                     

        $sequence_10 = { b8???????? e8???????? b860120000 e8???????? }
            // n = 4, score = 100
            //   b8????????           |                     
            //   e8????????           |                     
            //   b860120000           | mov                 eax, 0x1260
            //   e8????????           |                     

        $sequence_11 = { c3 b801000000 c3 55 8bec 6aff 68???????? }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   b801000000           | mov                 eax, 1
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   6aff                 | push                -1
            //   68????????           |                     

        $sequence_12 = { 59 66899da0f7ffff f3ab 66ab }
            // n = 4, score = 100
            //   59                   | pop                 ecx
            //   66899da0f7ffff       | mov                 word ptr [ebp - 0x860], bx
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax

        $sequence_13 = { 3bc6 59 894508 0f8409010000 6a04 56 }
            // n = 6, score = 100
            //   3bc6                 | cmp                 eax, esi
            //   59                   | pop                 ecx
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   0f8409010000         | je                  0x10f
            //   6a04                 | push                4
            //   56                   | push                esi

    condition:
        7 of them and filesize < 1695744
}