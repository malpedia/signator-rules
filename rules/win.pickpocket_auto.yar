rule win_pickpocket_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.pickpocket."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pickpocket"
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
        $sequence_0 = { 3bc7 760a b988d30000 e9???????? }
            // n = 4, score = 400
            //   3bc7                 | xor                 edi, edi
            //   760a                 | mov                 eax, dword ptr [esi + 0x28]
            //   b988d30000           | test                eax, eax
            //   e9????????           |                     

        $sequence_1 = { 7407 b935d70000 eb09 8bc7 }
            // n = 4, score = 400
            //   7407                 | dec                 eax
            //   b935d70000           | mov                 eax, dword ptr [edx + eax]
            //   eb09                 | dec                 eax
            //   8bc7                 | mov                 dword ptr [ecx + 8], eax

        $sequence_2 = { 7823 83e17f 0fb6c0 c1e107 03c8 }
            // n = 5, score = 400
            //   7823                 | mov                 ecx, edi
            //   83e17f               | dec                 eax
            //   0fb6c0               | mov                 ecx, edi
            //   c1e107               | inc                 ecx
            //   03c8                 | mov                 eax, 0x3e8

        $sequence_3 = { d3e0 a846 750f b99be00100 e8???????? }
            // n = 5, score = 400
            //   d3e0                 | mov                 esi, ecx
            //   a846                 | mov                 dword ptr [esp + 0x14], edx
            //   750f                 | sub                 esp, 0x24
            //   b99be00100           | push                ebx
            //   e8????????           |                     

        $sequence_4 = { b960cb0000 e8???????? eb02 33c0 }
            // n = 4, score = 400
            //   b960cb0000           | jl                  0xb5
            //   e8????????           |                     
            //   eb02                 | xor                 edi, edi
            //   33c0                 | mov                 dword ptr [ebp - 0x18], ebx

        $sequence_5 = { b97dcb0000 eb0c b96ccb0000 eb05 b960cb0000 e8???????? }
            // n = 6, score = 400
            //   b97dcb0000           | dec                 esp
            //   eb0c                 | mov                 eax, eax
            //   b96ccb0000           | mov                 eax, dword ptr [ebp - 0x75]
            //   eb05                 | je                  0x1ec1
            //   b960cb0000           | inc                 ebp
            //   e8????????           |                     

        $sequence_6 = { d3e0 a846 750f b99be00100 e8???????? e9???????? }
            // n = 6, score = 400
            //   d3e0                 | xor                 edi, edi
            //   a846                 | dec                 eax
            //   750f                 | test                eax, eax
            //   b99be00100           | jle                 0x18ea
            //   e8????????           |                     
            //   e9????????           |                     

        $sequence_7 = { 85c0 750f b9af770100 e8???????? e9???????? }
            // n = 5, score = 400
            //   85c0                 | dec                 eax
            //   750f                 | mov                 ecx, esi
            //   b9af770100           | dec                 eax
            //   e8????????           |                     
            //   e9????????           |                     

        $sequence_8 = { 741a b97dcb0000 eb0c b96ccb0000 eb05 b960cb0000 e8???????? }
            // n = 7, score = 400
            //   741a                 | cmp                 byte ptr [ebx + 0x89], 0
            //   b97dcb0000           | jne                 0x398
            //   eb0c                 | inc                 edx
            //   b96ccb0000           | test                byte ptr [eax + 4], dl
            //   eb05                 | jne                 0x448
            //   b960cb0000           | mov                 dword ptr [ecx + 0xc], eax
            //   e8????????           |                     

        $sequence_9 = { 7704 33c0 eb0a b952ca0000 }
            // n = 4, score = 400
            //   7704                 | lea                 esp, [edi + esi]
            //   33c0                 | dec                 eax
            //   eb0a                 | mov                 ebx, dword ptr [esp + 0x30]
            //   b952ca0000           | dec                 eax

    condition:
        7 of them and filesize < 1458176
}