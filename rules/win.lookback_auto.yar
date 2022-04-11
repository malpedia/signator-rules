rule win_lookback_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.lookback."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lookback"
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
        $sequence_0 = { c644241b00 895c2430 895c242c 895c241c }
            // n = 4, score = 200
            //   c644241b00           | mov                 byte ptr [esp + 0x1b], 0
            //   895c2430             | mov                 dword ptr [esp + 0x30], ebx
            //   895c242c             | mov                 dword ptr [esp + 0x2c], ebx
            //   895c241c             | mov                 dword ptr [esp + 0x1c], ebx

        $sequence_1 = { 25ffffff0f eb09 8b16 8bc7 }
            // n = 4, score = 200
            //   25ffffff0f           | and                 eax, 0xfffffff
            //   eb09                 | jmp                 0xb
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   8bc7                 | mov                 eax, edi

        $sequence_2 = { 50 ff15???????? 893d???????? 8b0d???????? }
            // n = 4, score = 200
            //   50                   | push                eax
            //   ff15????????         |                     
            //   893d????????         |                     
            //   8b0d????????         |                     

        $sequence_3 = { 02d3 8854240c 8b74240c 81e6ff000000 }
            // n = 4, score = 200
            //   02d3                 | add                 dl, bl
            //   8854240c             | mov                 byte ptr [esp + 0xc], dl
            //   8b74240c             | mov                 esi, dword ptr [esp + 0xc]
            //   81e6ff000000         | and                 esi, 0xff

        $sequence_4 = { c705????????00000000 5f b801000000 5b 83c420 c3 }
            // n = 6, score = 200
            //   c705????????00000000     |     
            //   5f                   | pop                 edi
            //   b801000000           | mov                 eax, 1
            //   5b                   | pop                 ebx
            //   83c420               | add                 esp, 0x20
            //   c3                   | ret                 

        $sequence_5 = { 5d 5b 59 c3 0594010000 8b08 894d00 }
            // n = 7, score = 200
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   0594010000           | add                 eax, 0x194
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   894d00               | mov                 dword ptr [ebp], ecx

        $sequence_6 = { 8b1d???????? 8b35???????? a1???????? 3bc7 740d 50 }
            // n = 6, score = 200
            //   8b1d????????         |                     
            //   8b35????????         |                     
            //   a1????????           |                     
            //   3bc7                 | cmp                 eax, edi
            //   740d                 | je                  0xf
            //   50                   | push                eax

        $sequence_7 = { 52 ffd6 8b442414 3bc7 0f8472010000 }
            // n = 5, score = 200
            //   52                   | push                edx
            //   ffd6                 | call                esi
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   3bc7                 | cmp                 eax, edi
            //   0f8472010000         | je                  0x178

        $sequence_8 = { 8b02 8b742420 03c7 8a18 }
            // n = 4, score = 200
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   8b742420             | mov                 esi, dword ptr [esp + 0x20]
            //   03c7                 | add                 eax, edi
            //   8a18                 | mov                 bl, byte ptr [eax]

        $sequence_9 = { 8945f8 60 648b1d18000000 64a130000000 }
            // n = 4, score = 200
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   60                   | pushal              
            //   648b1d18000000       | mov                 ebx, dword ptr fs:[0x18]
            //   64a130000000         | mov                 eax, dword ptr fs:[0x30]

    condition:
        7 of them and filesize < 131072
}