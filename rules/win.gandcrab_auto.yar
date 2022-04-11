rule win_gandcrab_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.gandcrab."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gandcrab"
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
        $sequence_0 = { ff15???????? ff774c 8bf0 ff15???????? 03c3 8d5e04 03d8 }
            // n = 7, score = 2100
            //   ff15????????         |                     
            //   ff774c               | push                dword ptr [edi + 0x4c]
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     
            //   03c3                 | add                 eax, ebx
            //   8d5e04               | lea                 ebx, dword ptr [esi + 4]
            //   03d8                 | add                 ebx, eax

        $sequence_1 = { 66894c46fe 8bc6 5e 5b }
            // n = 4, score = 2100
            //   66894c46fe           | mov                 word ptr [esi + eax*2 - 2], cx
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_2 = { ff15???????? ff7728 8bf0 ff15???????? 03c3 8d5e04 }
            // n = 6, score = 2100
            //   ff15????????         |                     
            //   ff7728               | push                dword ptr [edi + 0x28]
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     
            //   03c3                 | add                 eax, ebx
            //   8d5e04               | lea                 ebx, dword ptr [esi + 4]

        $sequence_3 = { 53 56 57 8bf9 33db 391f }
            // n = 6, score = 2100
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8bf9                 | mov                 edi, ecx
            //   33db                 | xor                 ebx, ebx
            //   391f                 | cmp                 dword ptr [edi], ebx

        $sequence_4 = { 741b ff772c ff15???????? ff7728 8bf0 }
            // n = 5, score = 2100
            //   741b                 | je                  0x1d
            //   ff772c               | push                dword ptr [edi + 0x2c]
            //   ff15????????         |                     
            //   ff7728               | push                dword ptr [edi + 0x28]
            //   8bf0                 | mov                 esi, eax

        $sequence_5 = { ff777c ff15???????? ff7778 8bf0 ff15???????? 03c3 }
            // n = 6, score = 2100
            //   ff777c               | push                dword ptr [edi + 0x7c]
            //   ff15????????         |                     
            //   ff7778               | push                dword ptr [edi + 0x78]
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     
            //   03c3                 | add                 eax, ebx

        $sequence_6 = { 03c3 8d5e04 03d8 837f2400 741b ff772c }
            // n = 6, score = 2100
            //   03c3                 | add                 eax, ebx
            //   8d5e04               | lea                 ebx, dword ptr [esi + 4]
            //   03d8                 | add                 ebx, eax
            //   837f2400             | cmp                 dword ptr [edi + 0x24], 0
            //   741b                 | je                  0x1d
            //   ff772c               | push                dword ptr [edi + 0x2c]

        $sequence_7 = { 741b ff7750 ff15???????? ff774c }
            // n = 4, score = 2100
            //   741b                 | je                  0x1d
            //   ff7750               | push                dword ptr [edi + 0x50]
            //   ff15????????         |                     
            //   ff774c               | push                dword ptr [edi + 0x4c]

        $sequence_8 = { ff7734 8bf0 ff15???????? 03c3 }
            // n = 4, score = 2100
            //   ff7734               | push                dword ptr [edi + 0x34]
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     
            //   03c3                 | add                 eax, ebx

        $sequence_9 = { 03c3 8d5e04 03d8 837f3000 741b }
            // n = 5, score = 2100
            //   03c3                 | add                 eax, ebx
            //   8d5e04               | lea                 ebx, dword ptr [esi + 4]
            //   03d8                 | add                 ebx, eax
            //   837f3000             | cmp                 dword ptr [edi + 0x30], 0
            //   741b                 | je                  0x1d

    condition:
        7 of them and filesize < 1024000
}