rule win_redpepper_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.redpepper."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redpepper"
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
        $sequence_0 = { 83c40c 33c0 3906 0f95c0 }
            // n = 4, score = 300
            //   83c40c               | add                 esp, 0xc
            //   33c0                 | xor                 eax, eax
            //   3906                 | cmp                 dword ptr [esi], eax
            //   0f95c0               | setne               al

        $sequence_1 = { 8b542418 50 52 ff510c 83c410 8bf0 }
            // n = 6, score = 300
            //   8b542418             | mov                 edx, dword ptr [esp + 0x18]
            //   50                   | push                eax
            //   52                   | push                edx
            //   ff510c               | call                dword ptr [ecx + 0xc]
            //   83c410               | add                 esp, 0x10
            //   8bf0                 | mov                 esi, eax

        $sequence_2 = { c3 8b442420 8b4c241c 896e0c 8b00 89461c }
            // n = 6, score = 300
            //   c3                   | ret                 
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   8b4c241c             | mov                 ecx, dword ptr [esp + 0x1c]
            //   896e0c               | mov                 dword ptr [esi + 0xc], ebp
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   89461c               | mov                 dword ptr [esi + 0x1c], eax

        $sequence_3 = { 3bc1 751b 6830010000 68???????? 6a41 }
            // n = 5, score = 300
            //   3bc1                 | cmp                 eax, ecx
            //   751b                 | jne                 0x1d
            //   6830010000           | push                0x130
            //   68????????           |                     
            //   6a41                 | push                0x41

        $sequence_4 = { 5b c3 83f802 0f85c7000000 }
            // n = 4, score = 300
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   83f802               | cmp                 eax, 2
            //   0f85c7000000         | jne                 0xcd

        $sequence_5 = { 85ff 0f848e000000 55 e8???????? 50 }
            // n = 5, score = 300
            //   85ff                 | test                edi, edi
            //   0f848e000000         | je                  0x94
            //   55                   | push                ebp
            //   e8????????           |                     
            //   50                   | push                eax

        $sequence_6 = { 83c42c 85c0 7522 6893020000 }
            // n = 4, score = 300
            //   83c42c               | add                 esp, 0x2c
            //   85c0                 | test                eax, eax
            //   7522                 | jne                 0x24
            //   6893020000           | push                0x293

        $sequence_7 = { e8???????? 8b4c2418 51 56 e8???????? 6898010000 68???????? }
            // n = 7, score = 300
            //   e8????????           |                     
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]
            //   51                   | push                ecx
            //   56                   | push                esi
            //   e8????????           |                     
            //   6898010000           | push                0x198
            //   68????????           |                     

        $sequence_8 = { 83d8ff 85c0 7510 5f 66c745001700 5e }
            // n = 6, score = 300
            //   83d8ff               | sbb                 eax, -1
            //   85c0                 | test                eax, eax
            //   7510                 | jne                 0x12
            //   5f                   | pop                 edi
            //   66c745001700         | mov                 word ptr [ebp], 0x17
            //   5e                   | pop                 esi

        $sequence_9 = { 83c404 56 e8???????? 83c404 c7472000000000 }
            // n = 5, score = 300
            //   83c404               | add                 esp, 4
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   c7472000000000       | mov                 dword ptr [edi + 0x20], 0

    condition:
        7 of them and filesize < 2482176
}