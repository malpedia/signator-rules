rule win_globeimposter_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.globeimposter."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.globeimposter"
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
        $sequence_0 = { 3901 1bc0 83c104 f7d8 }
            // n = 4, score = 700
            //   3901                 | cmp                 dword ptr [ecx], eax
            //   1bc0                 | sbb                 eax, eax
            //   83c104               | add                 ecx, 4
            //   f7d8                 | neg                 eax

        $sequence_1 = { 0f6e1f 0fd4cb 0f6e16 0ff4d0 }
            // n = 4, score = 700
            //   0f6e1f               | movd                mm3, dword ptr [edi]
            //   0fd4cb               | paddq               mm1, mm3
            //   0f6e16               | movd                mm2, dword ptr [esi]
            //   0ff4d0               | pmuludq             mm2, mm0

        $sequence_2 = { 75d7 5f 5b 5e 8bc2 }
            // n = 5, score = 700
            //   75d7                 | jne                 0xffffffd9
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx
            //   5e                   | pop                 esi
            //   8bc2                 | mov                 eax, edx

        $sequence_3 = { 3dfa000000 7205 6a0c 5f eb0d }
            // n = 5, score = 700
            //   3dfa000000           | cmp                 eax, 0xfa
            //   7205                 | jb                  7
            //   6a0c                 | push                0xc
            //   5f                   | pop                 edi
            //   eb0d                 | jmp                 0xf

        $sequence_4 = { 7411 8b4108 8d04b0 833800 7506 83e804 4e }
            // n = 7, score = 700
            //   7411                 | je                  0x13
            //   8b4108               | mov                 eax, dword ptr [ecx + 8]
            //   8d04b0               | lea                 eax, dword ptr [eax + esi*4]
            //   833800               | cmp                 dword ptr [eax], 0
            //   7506                 | jne                 8
            //   83e804               | sub                 eax, 4
            //   4e                   | dec                 esi

        $sequence_5 = { e8???????? 8bd0 85d2 7560 8b4508 8b4e08 }
            // n = 6, score = 700
            //   e8????????           |                     
            //   8bd0                 | mov                 edx, eax
            //   85d2                 | test                edx, edx
            //   7560                 | jne                 0x62
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]

        $sequence_6 = { 8b4604 40 8b4f04 3bc8 }
            // n = 4, score = 700
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   40                   | inc                 eax
            //   8b4f04               | mov                 ecx, dword ptr [edi + 4]
            //   3bc8                 | cmp                 ecx, eax

        $sequence_7 = { 6ac4 58 eb2f 56 ff750c }
            // n = 5, score = 700
            //   6ac4                 | push                -0x3c
            //   58                   | pop                 eax
            //   eb2f                 | jmp                 0x31
            //   56                   | push                esi
            //   ff750c               | push                dword ptr [ebp + 0xc]

        $sequence_8 = { 3b0424 1bc0 83c104 f7d8 }
            // n = 4, score = 700
            //   3b0424               | cmp                 eax, dword ptr [esp]
            //   1bc0                 | sbb                 eax, eax
            //   83c104               | add                 ecx, 4
            //   f7d8                 | neg                 eax

        $sequence_9 = { 8d7770 837e1001 7503 33ed }
            // n = 4, score = 700
            //   8d7770               | lea                 esi, dword ptr [edi + 0x70]
            //   837e1001             | cmp                 dword ptr [esi + 0x10], 1
            //   7503                 | jne                 5
            //   33ed                 | xor                 ebp, ebp

    condition:
        7 of them and filesize < 327680
}