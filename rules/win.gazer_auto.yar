rule win_gazer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.gazer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gazer"
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
        $sequence_0 = { ff15???????? 85c0 7511 e8???????? 84c0 7508 83c8ff }
            // n = 7, score = 300
            //   ff15????????         |                     
            //   85c0                 | inc                 ecx
            //   7511                 | inc                 edi
            //   e8????????           |                     
            //   84c0                 | dec                 eax
            //   7508                 | lea                 esi, dword ptr [esi + eax*2 + 6]
            //   83c8ff               | rep movsd           dword ptr es:[edi], dword ptr [esi]

        $sequence_1 = { 7511 e8???????? 84c0 7508 }
            // n = 4, score = 300
            //   7511                 | push                dword ptr [ebp - 0x18]
            //   e8????????           |                     
            //   84c0                 | call                esi
            //   7508                 | push                ebx

        $sequence_2 = { 85c0 7511 e8???????? 84c0 }
            // n = 4, score = 300
            //   85c0                 | je                  0x947
            //   7511                 | dec                 eax
            //   e8????????           |                     
            //   84c0                 | mov                 ecx, dword ptr [esi]

        $sequence_3 = { ff15???????? 85c0 7511 e8???????? 84c0 7508 }
            // n = 6, score = 300
            //   ff15????????         |                     
            //   85c0                 | lea                 eax, dword ptr [0x385c7]
            //   7511                 | dec                 esp
            //   e8????????           |                     
            //   84c0                 | cmovne              edx, eax
            //   7508                 | dec                 eax

        $sequence_4 = { 85c0 7511 e8???????? 84c0 7508 83c8ff }
            // n = 6, score = 300
            //   85c0                 | lea                 edx, dword ptr [ebp - 0x58]
            //   7511                 | inc                 ebp
            //   e8????????           |                     
            //   84c0                 | mov                 ecx, esi
            //   7508                 | dec                 esp
            //   83c8ff               | mov                 eax, edi

        $sequence_5 = { 85c0 7511 e8???????? 84c0 7508 83c8ff e9???????? }
            // n = 7, score = 300
            //   85c0                 | dec                 eax
            //   7511                 | lea                 ecx, dword ptr [ebp + 0xf]
            //   e8????????           |                     
            //   84c0                 | xor                 edx, edx
            //   7508                 | mov                 ebx, eax
            //   83c8ff               | test                eax, eax
            //   e9????????           |                     

        $sequence_6 = { 85c0 7511 e8???????? 84c0 7508 }
            // n = 5, score = 300
            //   85c0                 | pop                 ecx
            //   7511                 | push                0x100382b0
            //   e8????????           |                     
            //   84c0                 | push                eax
            //   7508                 | call                ebx

        $sequence_7 = { 7511 e8???????? 84c0 7508 83c8ff }
            // n = 5, score = 300
            //   7511                 | dec                 ecx
            //   e8????????           |                     
            //   84c0                 | mov                 edx, esi
            //   7508                 | inc                 ecx
            //   83c8ff               | mov                 dword ptr [esp + 8], eax

        $sequence_8 = { ff15???????? 85c0 7511 e8???????? 84c0 }
            // n = 5, score = 300
            //   ff15????????         |                     
            //   85c0                 | mov                 dword ptr [ebp + 0x68], ecx
            //   7511                 | mov                 ecx, dword ptr [ecx]
            //   e8????????           |                     
            //   84c0                 | xor                 dword ptr [ebp + 8], ecx

        $sequence_9 = { 7511 e8???????? 84c0 7508 83c8ff e9???????? }
            // n = 6, score = 300
            //   7511                 | mov                 dword ptr [ebx + 0x80], 1
            //   e8????????           |                     
            //   84c0                 | movups              xmm0, xmmword ptr [edi]
            //   7508                 | dec                 eax
            //   83c8ff               | lea                 edx, dword ptr [esp + 0x20]
            //   e9????????           |                     

    condition:
        7 of them and filesize < 950272
}