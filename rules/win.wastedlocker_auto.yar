rule win_wastedlocker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.wastedlocker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wastedlocker"
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
        $sequence_0 = { 7416 8b4508 ff7510 8d444302 50 894508 }
            // n = 6, score = 1000
            //   7416                 | je                  0x18
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   8d444302             | lea                 eax, [ebx + eax*2 + 2]
            //   50                   | push                eax
            //   894508               | mov                 dword ptr [ebp + 8], eax

        $sequence_1 = { 8d8704070000 50 8d85d0f3ffff 50 8bc6 }
            // n = 5, score = 1000
            //   8d8704070000         | lea                 eax, [edi + 0x704]
            //   50                   | push                eax
            //   8d85d0f3ffff         | lea                 eax, [ebp - 0xc30]
            //   50                   | push                eax
            //   8bc6                 | mov                 eax, esi

        $sequence_2 = { 89410c 5b c9 c20400 85d2 762c 56 }
            // n = 7, score = 1000
            //   89410c               | mov                 dword ptr [ecx + 0xc], eax
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   c20400               | ret                 4
            //   85d2                 | test                edx, edx
            //   762c                 | jbe                 0x2e
            //   56                   | push                esi

        $sequence_3 = { 83c40c 8d459c e8???????? 8d4704 }
            // n = 4, score = 1000
            //   83c40c               | add                 esp, 0xc
            //   8d459c               | lea                 eax, [ebp - 0x64]
            //   e8????????           |                     
            //   8d4704               | lea                 eax, [edi + 4]

        $sequence_4 = { 7711 85d2 7505 83fe01 7726 }
            // n = 5, score = 1000
            //   7711                 | ja                  0x13
            //   85d2                 | test                edx, edx
            //   7505                 | jne                 7
            //   83fe01               | cmp                 esi, 1
            //   7726                 | ja                  0x28

        $sequence_5 = { 7507 bee8000000 eb4e 8d4602 }
            // n = 4, score = 1000
            //   7507                 | jne                 9
            //   bee8000000           | mov                 esi, 0xe8
            //   eb4e                 | jmp                 0x50
            //   8d4602               | lea                 eax, [esi + 2]

        $sequence_6 = { ff35???????? ff15???????? 5f ff75f8 ff15???????? }
            // n = 5, score = 1000
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff15????????         |                     

        $sequence_7 = { ff7508 8d0436 e8???????? 6808040000 }
            // n = 4, score = 1000
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8d0436               | lea                 eax, [esi + esi]
            //   e8????????           |                     
            //   6808040000           | push                0x408

        $sequence_8 = { eb02 33ed 397c240c 745c 53 8b1d???????? }
            // n = 6, score = 1000
            //   eb02                 | jmp                 4
            //   33ed                 | xor                 ebp, ebp
            //   397c240c             | cmp                 dword ptr [esp + 0xc], edi
            //   745c                 | je                  0x5e
            //   53                   | push                ebx
            //   8b1d????????         |                     

        $sequence_9 = { 0fb75906 56 8d740818 57 }
            // n = 4, score = 1000
            //   0fb75906             | movzx               ebx, word ptr [ecx + 6]
            //   56                   | push                esi
            //   8d740818             | lea                 esi, [eax + ecx + 0x18]
            //   57                   | push                edi

    condition:
        7 of them and filesize < 147456
}