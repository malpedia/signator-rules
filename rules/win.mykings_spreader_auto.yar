rule win_mykings_spreader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.mykings_spreader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mykings_spreader"
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
        $sequence_0 = { 66c705????????0000 8b15???????? 85d2 7409 a1???????? ffd2 eb05 }
            // n = 7, score = 100
            //   66c705????????0000     |     
            //   8b15????????         |                     
            //   85d2                 | test                edx, edx
            //   7409                 | je                  0xb
            //   a1????????           |                     
            //   ffd2                 | call                edx
            //   eb05                 | jmp                 7

        $sequence_1 = { e8???????? 89c3 4b c745e400000000 3b5de4 7c1f ff4de4 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   89c3                 | mov                 ebx, eax
            //   4b                   | dec                 ebx
            //   c745e400000000       | mov                 dword ptr [ebp - 0x1c], 0
            //   3b5de4               | cmp                 ebx, dword ptr [ebp - 0x1c]
            //   7c1f                 | jl                  0x21
            //   ff4de4               | dec                 dword ptr [ebp - 0x1c]

        $sequence_2 = { 890424 7200 e9???????? eb00 52 7e00 e9???????? }
            // n = 7, score = 100
            //   890424               | mov                 dword ptr [esp], eax
            //   7200                 | jb                  2
            //   e9????????           |                     
            //   eb00                 | jmp                 2
            //   52                   | push                edx
            //   7e00                 | jle                 2
            //   e9????????           |                     

        $sequence_3 = { 8b45f8 e8???????? 89da 4a 6bd203 42 8d5410ff }
            // n = 7, score = 100
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   e8????????           |                     
            //   89da                 | mov                 edx, ebx
            //   4a                   | dec                 edx
            //   6bd203               | imul                edx, edx, 3
            //   42                   | inc                 edx
            //   8d5410ff             | lea                 edx, dword ptr [eax + edx - 1]

        $sequence_4 = { e9???????? ba???????? 8d4580 e8???????? 89d8 e8???????? 52 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   ba????????           |                     
            //   8d4580               | lea                 eax, dword ptr [ebp - 0x80]
            //   e8????????           |                     
            //   89d8                 | mov                 eax, ebx
            //   e8????????           |                     
            //   52                   | push                edx

        $sequence_5 = { 82a821b48a804a a1???????? 84a710c780d5 27 beae661a2a 4b cdf9 }
            // n = 7, score = 100
            //   82a821b48a804a       |                     
            //   a1????????           |                     
            //   84a710c780d5         | test                byte ptr [edi - 0x2a7f38f0], ah
            //   27                   | daa                 
            //   beae661a2a           | mov                 esi, 0x2a1a66ae
            //   4b                   | dec                 ebx
            //   cdf9                 | int                 0xf9

        $sequence_6 = { a1???????? 85c0 7407 a1???????? ffd0 833d????????00 7407 }
            // n = 7, score = 100
            //   a1????????           |                     
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   a1????????           |                     
            //   ffd0                 | call                eax
            //   833d????????00       |                     
            //   7407                 | je                  9

        $sequence_7 = { 6a00 e8???????? 8d7dcc 83c9ff 33c0 }
            // n = 5, score = 100
            //   6a00                 | push                0
            //   e8????????           |                     
            //   8d7dcc               | lea                 edi, dword ptr [ebp - 0x34]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax

        $sequence_8 = { 39f0 7f0f 89f1 8b15???????? 89d8 e8???????? 89d8 }
            // n = 7, score = 100
            //   39f0                 | cmp                 eax, esi
            //   7f0f                 | jg                  0x11
            //   89f1                 | mov                 ecx, esi
            //   8b15????????         |                     
            //   89d8                 | mov                 eax, ebx
            //   e8????????           |                     
            //   89d8                 | mov                 eax, ebx

        $sequence_9 = { 8b55f8 8b45fc 8b4dfc 8b09 ff91c0000000 8b45f8 8b5014 }
            // n = 7, score = 100
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8b09                 | mov                 ecx, dword ptr [ecx]
            //   ff91c0000000         | call                dword ptr [ecx + 0xc0]
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8b5014               | mov                 edx, dword ptr [eax + 0x14]

    condition:
        7 of them and filesize < 1581056
}