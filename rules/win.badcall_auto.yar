rule win_badcall_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.badcall."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.badcall"
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
        $sequence_0 = { ff15???????? 8b5604 8d4c2408 6a10 51 52 }
            // n = 6, score = 300
            //   ff15????????         |                     
            //   8b5604               | mov                 edx, dword ptr [esi + 4]
            //   8d4c2408             | lea                 ecx, dword ptr [esp + 8]
            //   6a10                 | push                0x10
            //   51                   | push                ecx
            //   52                   | push                edx

        $sequence_1 = { 7557 33c0 68???????? a3???????? a3???????? a3???????? a1???????? }
            // n = 7, score = 300
            //   7557                 | jne                 0x59
            //   33c0                 | xor                 eax, eax
            //   68????????           |                     
            //   a3????????           |                     
            //   a3????????           |                     
            //   a3????????           |                     
            //   a1????????           |                     

        $sequence_2 = { c20400 c705????????01000000 a1???????? 68???????? }
            // n = 4, score = 300
            //   c20400               | ret                 4
            //   c705????????01000000     |     
            //   a1????????           |                     
            //   68????????           |                     

        $sequence_3 = { 68???????? 6802000080 ff15???????? 85c0 0f85a9000000 8b542408 }
            // n = 6, score = 300
            //   68????????           |                     
            //   6802000080           | push                0x80000002
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f85a9000000         | jne                 0xaf
            //   8b542408             | mov                 edx, dword ptr [esp + 8]

        $sequence_4 = { e8???????? 8d4e2c e8???????? 5e }
            // n = 4, score = 300
            //   e8????????           |                     
            //   8d4e2c               | lea                 ecx, dword ptr [esi + 0x2c]
            //   e8????????           |                     
            //   5e                   | pop                 esi

        $sequence_5 = { 7434 83e803 7557 33c0 }
            // n = 4, score = 300
            //   7434                 | je                  0x36
            //   83e803               | sub                 eax, 3
            //   7557                 | jne                 0x59
            //   33c0                 | xor                 eax, eax

        $sequence_6 = { 48 7455 48 7434 }
            // n = 4, score = 300
            //   48                   | dec                 eax
            //   7455                 | je                  0x57
            //   48                   | dec                 eax
            //   7434                 | je                  0x36

        $sequence_7 = { e8???????? 83f801 750d 8d4c242c }
            // n = 4, score = 300
            //   e8????????           |                     
            //   83f801               | cmp                 eax, 1
            //   750d                 | jne                 0xf
            //   8d4c242c             | lea                 ecx, dword ptr [esp + 0x2c]

        $sequence_8 = { 83c408 8bce 6a17 6a01 }
            // n = 4, score = 300
            //   83c408               | add                 esp, 8
            //   8bce                 | mov                 ecx, esi
            //   6a17                 | push                0x17
            //   6a01                 | push                1

        $sequence_9 = { a3???????? a1???????? 50 c705????????04000000 }
            // n = 4, score = 300
            //   a3????????           |                     
            //   a1????????           |                     
            //   50                   | push                eax
            //   c705????????04000000     |     

        $sequence_10 = { c705????????04000000 ff15???????? c20400 a1???????? 68???????? 50 }
            // n = 6, score = 300
            //   c705????????04000000     |     
            //   ff15????????         |                     
            //   c20400               | ret                 4
            //   a1????????           |                     
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_11 = { 85c0 75d3 5f 33c0 5e }
            // n = 5, score = 300
            //   85c0                 | test                eax, eax
            //   75d3                 | jne                 0xffffffd5
            //   5f                   | pop                 edi
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi

        $sequence_12 = { 53 55 56 8bf1 0f84ff000000 8bac2428020000 6685ed }
            // n = 7, score = 300
            //   53                   | push                ebx
            //   55                   | push                ebp
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   0f84ff000000         | je                  0x105
            //   8bac2428020000       | mov                 ebp, dword ptr [esp + 0x228]
            //   6685ed               | test                bp, bp

        $sequence_13 = { 7ce1 33c0 3bf7 5f }
            // n = 4, score = 300
            //   7ce1                 | jl                  0xffffffe3
            //   33c0                 | xor                 eax, eax
            //   3bf7                 | cmp                 esi, edi
            //   5f                   | pop                 edi

        $sequence_14 = { 85c0 0f8642010000 8b4608 85c0 7568 8b4658 }
            // n = 6, score = 200
            //   85c0                 | test                eax, eax
            //   0f8642010000         | jbe                 0x148
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   85c0                 | test                eax, eax
            //   7568                 | jne                 0x6a
            //   8b4658               | mov                 eax, dword ptr [esi + 0x58]

        $sequence_15 = { e8???????? 83c410 83f801 0f85f7000000 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   83f801               | cmp                 eax, 1
            //   0f85f7000000         | jne                 0xfd

    condition:
        7 of them and filesize < 483328
}