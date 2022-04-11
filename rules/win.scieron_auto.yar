rule win_scieron_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.scieron."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.scieron"
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
        $sequence_0 = { e9???????? 53 55 55 }
            // n = 4, score = 100
            //   e9????????           |                     
            //   53                   | push                ebx
            //   55                   | push                ebp
            //   55                   | push                ebp

        $sequence_1 = { e8???????? 8bf8 83c410 3bfe 0f841bffffff 8b7508 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   83c410               | add                 esp, 0x10
            //   3bfe                 | cmp                 edi, esi
            //   0f841bffffff         | je                  0xffffff21
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]

        $sequence_2 = { 6a18 8d8600400010 50 8d443c30 50 ffd3 }
            // n = 6, score = 100
            //   6a18                 | push                0x18
            //   8d8600400010         | lea                 eax, dword ptr [esi + 0x10004000]
            //   50                   | push                eax
            //   8d443c30             | lea                 eax, dword ptr [esp + edi + 0x30]
            //   50                   | push                eax
            //   ffd3                 | call                ebx

        $sequence_3 = { 685cee0000 8935???????? ff15???????? 68???????? 8d85e0feffff }
            // n = 5, score = 100
            //   685cee0000           | push                0xee5c
            //   8935????????         |                     
            //   ff15????????         |                     
            //   68????????           |                     
            //   8d85e0feffff         | lea                 eax, dword ptr [ebp - 0x120]

        $sequence_4 = { 56 ff75f0 8bf0 e8???????? 83c40c 8bf0 }
            // n = 6, score = 100
            //   56                   | push                esi
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8bf0                 | mov                 esi, eax

        $sequence_5 = { 6bf61c 8b88c0410010 ff742414 898e08400010 8b88dc410010 898e00400010 }
            // n = 6, score = 100
            //   6bf61c               | imul                esi, esi, 0x1c
            //   8b88c0410010         | mov                 ecx, dword ptr [eax + 0x100041c0]
            //   ff742414             | push                dword ptr [esp + 0x14]
            //   898e08400010         | mov                 dword ptr [esi + 0x10004008], ecx
            //   8b88dc410010         | mov                 ecx, dword ptr [eax + 0x100041dc]
            //   898e00400010         | mov                 dword ptr [esi + 0x10004000], ecx

        $sequence_6 = { 5f 5e 5d 59 59 c3 ff742414 }
            // n = 7, score = 100
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   ff742414             | push                dword ptr [esp + 0x14]

        $sequence_7 = { 6a40 ffd7 85c0 7414 6a00 }
            // n = 5, score = 100
            //   6a40                 | push                0x40
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax
            //   7414                 | je                  0x16
            //   6a00                 | push                0

        $sequence_8 = { 7475 817c2410c8000000 756b 33c0 40 }
            // n = 5, score = 100
            //   7475                 | je                  0x77
            //   817c2410c8000000     | cmp                 dword ptr [esp + 0x10], 0xc8
            //   756b                 | jne                 0x6d
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax

        $sequence_9 = { ffb600020000 ffb614020000 68???????? 55 ffd3 50 }
            // n = 6, score = 100
            //   ffb600020000         | push                dword ptr [esi + 0x200]
            //   ffb614020000         | push                dword ptr [esi + 0x214]
            //   68????????           |                     
            //   55                   | push                ebp
            //   ffd3                 | call                ebx
            //   50                   | push                eax

    condition:
        7 of them and filesize < 100352
}