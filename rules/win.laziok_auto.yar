rule win_laziok_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.laziok."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.laziok"
        malpedia_rule_date = "20220513"
        malpedia_hash = "7f4b2229e6ae614d86d74917f6d5b41890e62a26"
        malpedia_version = "20220516"
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
        $sequence_0 = { 68???????? 6a10 6858020000 e8???????? a3???????? }
            // n = 5, score = 900
            //   68????????           |                     
            //   6a10                 | push                0x10
            //   6858020000           | push                0x258
            //   e8????????           |                     
            //   a3????????           |                     

        $sequence_1 = { 56 8b742408 833e01 7513 ff7608 ff15???????? 8b460c }
            // n = 7, score = 900
            //   56                   | push                esi
            //   8b742408             | mov                 esi, dword ptr [esp + 8]
            //   833e01               | cmp                 dword ptr [esi], 1
            //   7513                 | jne                 0x15
            //   ff7608               | push                dword ptr [esi + 8]
            //   ff15????????         |                     
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]

        $sequence_2 = { ff15???????? c6043800 8bc7 5f 5e 5d 5b }
            // n = 7, score = 900
            //   ff15????????         |                     
            //   c6043800             | mov                 byte ptr [eax + edi], 0
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx

        $sequence_3 = { 56 e8???????? 59 8b4c240c 03c6 8901 8bc6 }
            // n = 7, score = 900
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8b4c240c             | mov                 ecx, dword ptr [esp + 0xc]
            //   03c6                 | add                 eax, esi
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8bc6                 | mov                 eax, esi

        $sequence_4 = { 57 ff74240c 33f6 ff35???????? e8???????? 8bf8 }
            // n = 6, score = 900
            //   57                   | push                edi
            //   ff74240c             | push                dword ptr [esp + 0xc]
            //   33f6                 | xor                 esi, esi
            //   ff35????????         |                     
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax

        $sequence_5 = { 56 6a00 ff35???????? ff15???????? eb0c 56 83c028 }
            // n = 7, score = 900
            //   56                   | push                esi
            //   6a00                 | push                0
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   eb0c                 | jmp                 0xe
            //   56                   | push                esi
            //   83c028               | add                 eax, 0x28

        $sequence_6 = { 33f6 e8???????? 59 59 85c0 740a }
            // n = 6, score = 900
            //   33f6                 | xor                 esi, esi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   740a                 | je                  0xc

        $sequence_7 = { 8bf8 39742410 741b ff742410 ff15???????? 8bf0 85f6 }
            // n = 7, score = 900
            //   8bf8                 | mov                 edi, eax
            //   39742410             | cmp                 dword ptr [esp + 0x10], esi
            //   741b                 | je                  0x1d
            //   ff742410             | push                dword ptr [esp + 0x10]
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi

    condition:
        7 of them and filesize < 688128
}