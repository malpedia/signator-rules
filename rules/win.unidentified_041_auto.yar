rule win_unidentified_041_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.unidentified_041."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_041"
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
        $sequence_0 = { 33c0 8bbdc8fdffff 6bc009 0fb6bc38e8d74600 8bc7 89bdc8fdffff 8bbde4fdffff }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   8bbdc8fdffff         | mov                 edi, dword ptr [ebp - 0x238]
            //   6bc009               | imul                eax, eax, 9
            //   0fb6bc38e8d74600     | movzx               edi, byte ptr [eax + edi + 0x46d7e8]
            //   8bc7                 | mov                 eax, edi
            //   89bdc8fdffff         | mov                 dword ptr [ebp - 0x238], edi
            //   8bbde4fdffff         | mov                 edi, dword ptr [ebp - 0x21c]

        $sequence_1 = { ff742470 e9???????? 8bca e8???????? 8ad0 8d8c24a0000000 e8???????? }
            // n = 7, score = 200
            //   ff742470             | push                dword ptr [esp + 0x70]
            //   e9????????           |                     
            //   8bca                 | mov                 ecx, edx
            //   e8????????           |                     
            //   8ad0                 | mov                 dl, al
            //   8d8c24a0000000       | lea                 ecx, dword ptr [esp + 0xa0]
            //   e8????????           |                     

        $sequence_2 = { 8bb548fdffff 8d8d10fdffff 57 e8???????? c645fc09 8b08 85c9 }
            // n = 7, score = 200
            //   8bb548fdffff         | mov                 esi, dword ptr [ebp - 0x2b8]
            //   8d8d10fdffff         | lea                 ecx, dword ptr [ebp - 0x2f0]
            //   57                   | push                edi
            //   e8????????           |                     
            //   c645fc09             | mov                 byte ptr [ebp - 4], 9
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   85c9                 | test                ecx, ecx

        $sequence_3 = { 8b4d10 8d0441 50 e8???????? 8b4d14 83c40c 837e1408 }
            // n = 7, score = 200
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   8d0441               | lea                 eax, dword ptr [ecx + eax*2]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]
            //   83c40c               | add                 esp, 0xc
            //   837e1408             | cmp                 dword ptr [esi + 0x14], 8

        $sequence_4 = { 75f1 5f 8b0b 8b55f0 8b45ec 5e 5b }
            // n = 7, score = 200
            //   75f1                 | jne                 0xfffffff3
            //   5f                   | pop                 edi
            //   8b0b                 | mov                 ecx, dword ptr [ebx]
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_5 = { ffd6 84db c645fc18 8b8530fdffff 0f94c3 85c0 740a }
            // n = 7, score = 200
            //   ffd6                 | call                esi
            //   84db                 | test                bl, bl
            //   c645fc18             | mov                 byte ptr [ebp - 4], 0x18
            //   8b8530fdffff         | mov                 eax, dword ptr [ebp - 0x2d0]
            //   0f94c3               | sete                bl
            //   85c0                 | test                eax, eax
            //   740a                 | je                  0xc

        $sequence_6 = { ff15???????? 8b4c2448 85c9 75c7 85c0 750e 8b842488000000 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   8b4c2448             | mov                 ecx, dword ptr [esp + 0x48]
            //   85c9                 | test                ecx, ecx
            //   75c7                 | jne                 0xffffffc9
            //   85c0                 | test                eax, eax
            //   750e                 | jne                 0x10
            //   8b842488000000       | mov                 eax, dword ptr [esp + 0x88]

        $sequence_7 = { 8b7508 33d2 8955dc 8975e0 c746140f000000 895610 8816 }
            // n = 7, score = 200
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   33d2                 | xor                 edx, edx
            //   8955dc               | mov                 dword ptr [ebp - 0x24], edx
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi
            //   c746140f000000       | mov                 dword ptr [esi + 0x14], 0xf
            //   895610               | mov                 dword ptr [esi + 0x10], edx
            //   8816                 | mov                 byte ptr [esi], dl

        $sequence_8 = { 50 ff5108 eb02 33db 8b9560fdffff 8b8d5cfdffff }
            // n = 6, score = 200
            //   50                   | push                eax
            //   ff5108               | call                dword ptr [ecx + 8]
            //   eb02                 | jmp                 4
            //   33db                 | xor                 ebx, ebx
            //   8b9560fdffff         | mov                 edx, dword ptr [ebp - 0x2a0]
            //   8b8d5cfdffff         | mov                 ecx, dword ptr [ebp - 0x2a4]

        $sequence_9 = { 8d4c2414 e8???????? 8b4508 8b4c2428 64890d00000000 59 8be5 }
            // n = 7, score = 200
            //   8d4c2414             | lea                 ecx, dword ptr [esp + 0x14]
            //   e8????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b4c2428             | mov                 ecx, dword ptr [esp + 0x28]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   59                   | pop                 ecx
            //   8be5                 | mov                 esp, ebp

    condition:
        7 of them and filesize < 1097728
}