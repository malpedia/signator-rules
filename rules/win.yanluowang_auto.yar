rule win_yanluowang_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.yanluowang."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.yanluowang"
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
        $sequence_0 = { 7402 8b3a 8b55c0 33fe 8d700c 33d7 85f6 }
            // n = 7, score = 100
            //   7402                 | je                  4
            //   8b3a                 | mov                 edi, dword ptr [edx]
            //   8b55c0               | mov                 edx, dword ptr [ebp - 0x40]
            //   33fe                 | xor                 edi, esi
            //   8d700c               | lea                 esi, dword ptr [eax + 0xc]
            //   33d7                 | xor                 edx, edi
            //   85f6                 | test                esi, esi

        $sequence_1 = { e9???????? 8d4d30 e9???????? 8d4d48 e9???????? 8d4d60 e9???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8d4d30               | lea                 ecx, dword ptr [ebp + 0x30]
            //   e9????????           |                     
            //   8d4d48               | lea                 ecx, dword ptr [ebp + 0x48]
            //   e9????????           |                     
            //   8d4d60               | lea                 ecx, dword ptr [ebp + 0x60]
            //   e9????????           |                     

        $sequence_2 = { 59 8bc6 5e 8be5 5d c3 e9???????? }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   e9????????           |                     

        $sequence_3 = { 8bd7 c1fa06 8934b8 8bc7 83e03f 6bc830 8b049538034600 }
            // n = 7, score = 100
            //   8bd7                 | mov                 edx, edi
            //   c1fa06               | sar                 edx, 6
            //   8934b8               | mov                 dword ptr [eax + edi*4], esi
            //   8bc7                 | mov                 eax, edi
            //   83e03f               | and                 eax, 0x3f
            //   6bc830               | imul                ecx, eax, 0x30
            //   8b049538034600       | mov                 eax, dword ptr [edx*4 + 0x460338]

        $sequence_4 = { 8bd0 8b0a eb0f 33c9 c745fc02000000 894df8 8d55f8 }
            // n = 7, score = 100
            //   8bd0                 | mov                 edx, eax
            //   8b0a                 | mov                 ecx, dword ptr [edx]
            //   eb0f                 | jmp                 0x11
            //   33c9                 | xor                 ecx, ecx
            //   c745fc02000000       | mov                 dword ptr [ebp - 4], 2
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   8d55f8               | lea                 edx, dword ptr [ebp - 8]

        $sequence_5 = { 8b442414 c703???????? 83f808 7709 8b1485c0874400 eb3f 83f810 }
            // n = 7, score = 100
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   c703????????         |                     
            //   83f808               | cmp                 eax, 8
            //   7709                 | ja                  0xb
            //   8b1485c0874400       | mov                 edx, dword ptr [eax*4 + 0x4487c0]
            //   eb3f                 | jmp                 0x41
            //   83f810               | cmp                 eax, 0x10

        $sequence_6 = { 40 89bd84fdffff 898588fdffff 83f802 7d0b 8b8d6cfdffff }
            // n = 6, score = 100
            //   40                   | inc                 eax
            //   89bd84fdffff         | mov                 dword ptr [ebp - 0x27c], edi
            //   898588fdffff         | mov                 dword ptr [ebp - 0x278], eax
            //   83f802               | cmp                 eax, 2
            //   7d0b                 | jge                 0xd
            //   8b8d6cfdffff         | mov                 ecx, dword ptr [ebp - 0x294]

        $sequence_7 = { 33c0 85c9 7402 8b01 8b5dbc 33c6 33d8 }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   85c9                 | test                ecx, ecx
            //   7402                 | je                  4
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   8b5dbc               | mov                 ebx, dword ptr [ebp - 0x44]
            //   33c6                 | xor                 eax, esi
            //   33d8                 | xor                 ebx, eax

        $sequence_8 = { 894db4 752f dd45b0 51 51 dd1c24 }
            // n = 6, score = 100
            //   894db4               | mov                 dword ptr [ebp - 0x4c], ecx
            //   752f                 | jne                 0x31
            //   dd45b0               | fld                 qword ptr [ebp - 0x50]
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   dd1c24               | fstp                qword ptr [esp]

        $sequence_9 = { 8b45f8 8b4dc0 c1e808 33c8 c1c607 33ca 0fb6c3 }
            // n = 7, score = 100
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8b4dc0               | mov                 ecx, dword ptr [ebp - 0x40]
            //   c1e808               | shr                 eax, 8
            //   33c8                 | xor                 ecx, eax
            //   c1c607               | rol                 esi, 7
            //   33ca                 | xor                 ecx, edx
            //   0fb6c3               | movzx               eax, bl

    condition:
        7 of them and filesize < 834560
}