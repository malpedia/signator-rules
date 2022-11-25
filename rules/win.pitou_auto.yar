rule win_pitou_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.pitou."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pitou"
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
        $sequence_0 = { 33c0 ac 8bda c1e305 03c3 8bda c1eb02 }
            // n = 7, score = 700
            //   33c0                 | sbb                 al, 0x34
            //   ac                   | cmp                 dword ptr [edi], eax
            //   8bda                 | pop                 es
            //   c1e305               | hlt                 
            //   03c3                 | pop                 ds
            //   8bda                 | sbb                 al, 0x57
            //   c1eb02               | cmp                 eax, 0x769b00a

        $sequence_1 = { 8bda c1e305 03c3 8bda c1eb02 }
            // n = 5, score = 700
            //   8bda                 | mov                 dword ptr [ebp - 0x23c], eax
            //   c1e305               | jmp                 0x5c
            //   03c3                 | mov                 eax, dword ptr [ebp - 0x23c]
            //   8bda                 | mov                 eax, dword ptr [ebp - 0x13c]
            //   c1eb02               | add                 eax, dword ptr [ebp + edx*4 - 0x138]

        $sequence_2 = { 8a6201 80f457 8acc 80e103 8aec c0ed03 80e507 }
            // n = 7, score = 700
            //   8a6201               | test                eax, eax
            //   80f457               | je                  0xffffef91
            //   8acc                 | cmp                 bx, word ptr [eax + 6]
            //   80e103               | jb                  0x5464
            //   8aec                 | cmp                 si, word ptr [edi + 4]
            //   c0ed03               | ja                  0x5464
            //   80e507               | mov                 dword ptr [edx], ecx

        $sequence_3 = { 8a6201 80f457 8acc 80e103 }
            // n = 4, score = 700
            //   8a6201               | jge                 0xffff429f
            //   80f457               | inc                 ecx
            //   8acc                 | dec                 eax
            //   80e103               | inc                 ecx

        $sequence_4 = { ac 8bda c1e305 03c3 8bda c1eb02 }
            // n = 6, score = 700
            //   ac                   | lahf                
            //   8bda                 | push                edi
            //   c1e305               | pop                 edi
            //   03c3                 | xor                 eax, 0x149a0332
            //   8bda                 | imul                eax, dword ptr [esi - 0x37dc318], 0x11da03ff
            //   c1eb02               | xor                 ebx, dword ptr [edx + 0x17]

        $sequence_5 = { 80f457 8acc 80e103 8aec }
            // n = 4, score = 700
            //   80f457               | cmp                 word ptr [eax + 0x20], dx
            //   8acc                 | jne                 0xfffec0c6
            //   80e103               | mov                 bx, word ptr [ebp + 8]
            //   8aec                 | cmp                 word ptr [eax + 0x22], bx

        $sequence_6 = { 8afb 80e703 c0eb05 80e303 80ff00 }
            // n = 5, score = 700
            //   8afb                 | cmp                 eax, ebx
            //   80e703               | jne                 0x6d5f
            //   c0eb05               | mov                 dword ptr [ebp - 8], ebx
            //   80e303               | mov                 dword ptr [ebp - 0xc], ebx
            //   80ff00               | mov                 dword ptr [ebp - 0x10], ebx

        $sequence_7 = { ac 8bda c1e305 03c3 8bda }
            // n = 5, score = 700
            //   ac                   | push                ebx
            //   8bda                 | adc                 eax, 0xe8063205
            //   c1e305               | mov                 eax, 0x3fffd53
            //   03c3                 | lahf                
            //   8bda                 | push                edi

        $sequence_8 = { 8acc 80e103 8aec c0ed03 }
            // n = 4, score = 700
            //   8acc                 | mov                 byte ptr [esi + 6], al
            //   80e103               | cmp                 al, 0xf
            //   8aec                 | jne                 0xd863
            //   c0ed03               | mov                 al, byte ptr [ebx]

        $sequence_9 = { 8acc 80e103 8aec c0ed03 80e507 }
            // n = 5, score = 700
            //   8acc                 | je                  0xbd72
            //   80e103               | xor                 eax, eax
            //   8aec                 | mov                 dword ptr [ebp - 0x1c], ebx
            //   c0ed03               | mov                 dword ptr [ebp - 0x28], ebx
            //   80e507               | cmp                 edi, ebx

    condition:
        7 of them and filesize < 1106944
}