rule win_chthonic_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.chthonic."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chthonic"
        malpedia_rule_date = "20211007"
        malpedia_hash = "e5b790e0f888f252d49063a1251ca60ec2832535"
        malpedia_version = "20211008"
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
        $sequence_0 = { 6a1f c1e91f 5f 894dfc e9???????? 0fb60c1a }
            // n = 6, score = 600
            //   6a1f                 | push                0x1f
            //   c1e91f               | shr                 ecx, 0x1f
            //   5f                   | pop                 edi
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   e9????????           |                     
            //   0fb60c1a             | movzx               ecx, byte ptr [edx + ebx]

        $sequence_1 = { 0f850d010000 8b4df0 eb00 894df8 }
            // n = 4, score = 600
            //   0f850d010000         | jne                 0x113
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   eb00                 | jmp                 2
            //   894df8               | mov                 dword ptr [ebp - 8], ecx

        $sequence_2 = { 8911 8b00 8b4d08 03c2 25ff000080 }
            // n = 5, score = 600
            //   8911                 | mov                 dword ptr [ecx], edx
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   03c2                 | add                 eax, edx
            //   25ff000080           | and                 eax, 0x800000ff

        $sequence_3 = { 89450c 8b00 85c0 0f8505000000 }
            // n = 4, score = 600
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   85c0                 | test                eax, eax
            //   0f8505000000         | jne                 0xb

        $sequence_4 = { c3 8b442404 8b08 53 8a5902 }
            // n = 5, score = 600
            //   c3                   | ret                 
            //   8b442404             | mov                 eax, dword ptr [esp + 4]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   53                   | push                ebx
            //   8a5902               | mov                 bl, byte ptr [ecx + 2]

        $sequence_5 = { 7908 4e 81ce00ffffff 46 8d84b5fcfbffff }
            // n = 5, score = 600
            //   7908                 | jns                 0xa
            //   4e                   | dec                 esi
            //   81ce00ffffff         | or                  esi, 0xffffff00
            //   46                   | inc                 esi
            //   8d84b5fcfbffff       | lea                 eax, dword ptr [ebp + esi*4 - 0x404]

        $sequence_6 = { ff7514 53 ff7510 ff7508 e8???????? 85c0 7502 }
            // n = 7, score = 600
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   53                   | push                ebx
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7502                 | jne                 4

        $sequence_7 = { 880c33 42 8b5d08 ebd3 c745f801000000 85ff }
            // n = 6, score = 600
            //   880c33               | mov                 byte ptr [ebx + esi], cl
            //   42                   | inc                 edx
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   ebd3                 | jmp                 0xffffffd5
            //   c745f801000000       | mov                 dword ptr [ebp - 8], 1
            //   85ff                 | test                edi, edi

        $sequence_8 = { 8bf0 83c204 5f c1ee1f e9???????? }
            // n = 5, score = 600
            //   8bf0                 | mov                 esi, eax
            //   83c204               | add                 edx, 4
            //   5f                   | pop                 edi
            //   c1ee1f               | shr                 esi, 0x1f
            //   e9????????           |                     

        $sequence_9 = { 8d0c4e 894df8 85ff 0f845d010000 4f 8bf0 8bcf }
            // n = 7, score = 600
            //   8d0c4e               | lea                 ecx, dword ptr [esi + ecx*2]
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   85ff                 | test                edi, edi
            //   0f845d010000         | je                  0x163
            //   4f                   | dec                 edi
            //   8bf0                 | mov                 esi, eax
            //   8bcf                 | mov                 ecx, edi

    condition:
        7 of them and filesize < 425984
}