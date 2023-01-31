rule win_comlook_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.comlook."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.comlook"
        malpedia_rule_date = "20230124"
        malpedia_hash = "2ee0eebba83dce3d019a90519f2f972c0fcf9686"
        malpedia_version = "20230125"
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
        $sequence_0 = { e8???????? b012 8b4c2450 64890d00000000 59 5f 5e }
            // n = 7, score = 100
            //   e8????????           |                     
            //   b012                 | mov                 al, 0x12
            //   8b4c2450             | mov                 ecx, dword ptr [esp + 0x50]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   59                   | pop                 ecx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_1 = { 8b5144 895594 837d9400 0f84eb000000 8b4594 83780400 742f }
            // n = 7, score = 100
            //   8b5144               | mov                 edx, dword ptr [ecx + 0x44]
            //   895594               | mov                 dword ptr [ebp - 0x6c], edx
            //   837d9400             | cmp                 dword ptr [ebp - 0x6c], 0
            //   0f84eb000000         | je                  0xf1
            //   8b4594               | mov                 eax, dword ptr [ebp - 0x6c]
            //   83780400             | cmp                 dword ptr [eax + 4], 0
            //   742f                 | je                  0x31

        $sequence_2 = { e9???????? 8d45ac 50 e8???????? c3 8d45a4 50 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8d45ac               | lea                 eax, [ebp - 0x54]
            //   50                   | push                eax
            //   e8????????           |                     
            //   c3                   | ret                 
            //   8d45a4               | lea                 eax, [ebp - 0x5c]
            //   50                   | push                eax

        $sequence_3 = { 8d8d60ffffff 51 8d956cffffff 52 8b45f4 50 ff15???????? }
            // n = 7, score = 100
            //   8d8d60ffffff         | lea                 ecx, [ebp - 0xa0]
            //   51                   | push                ecx
            //   8d956cffffff         | lea                 edx, [ebp - 0x94]
            //   52                   | push                edx
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_4 = { 8b4d0c 81c1ac000000 8b10 8911 8b5004 895104 8b5008 }
            // n = 7, score = 100
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   81c1ac000000         | add                 ecx, 0xac
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   8911                 | mov                 dword ptr [ecx], edx
            //   8b5004               | mov                 edx, dword ptr [eax + 4]
            //   895104               | mov                 dword ptr [ecx + 4], edx
            //   8b5008               | mov                 edx, dword ptr [eax + 8]

        $sequence_5 = { e8???????? 83ec0c c745fc00000000 8bcc 8965f0 50 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83ec0c               | sub                 esp, 0xc
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   8bcc                 | mov                 ecx, esp
            //   8965f0               | mov                 dword ptr [ebp - 0x10], esp
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_6 = { e8???????? 8bc8 83c40c 894c2414 85c9 0f84b5020000 8b754c }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax
            //   83c40c               | add                 esp, 0xc
            //   894c2414             | mov                 dword ptr [esp + 0x14], ecx
            //   85c9                 | test                ecx, ecx
            //   0f84b5020000         | je                  0x2bb
            //   8b754c               | mov                 esi, dword ptr [ebp + 0x4c]

        $sequence_7 = { eb45 8b55f8 8b827c4c0000 50 8b8a784c0000 51 8b55f8 }
            // n = 7, score = 100
            //   eb45                 | jmp                 0x47
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   8b827c4c0000         | mov                 eax, dword ptr [edx + 0x4c7c]
            //   50                   | push                eax
            //   8b8a784c0000         | mov                 ecx, dword ptr [edx + 0x4c78]
            //   51                   | push                ecx
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]

        $sequence_8 = { e9???????? c685f4feffff00 837d0800 7459 8b5508 52 e8???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   c685f4feffff00       | mov                 byte ptr [ebp - 0x10c], 0
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   7459                 | je                  0x5b
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_9 = { e9???????? eb0b 33d2 75fc c745f400000000 8b4510 894594 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   eb0b                 | jmp                 0xd
            //   33d2                 | xor                 edx, edx
            //   75fc                 | jne                 0xfffffffe
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   894594               | mov                 dword ptr [ebp - 0x6c], eax

    condition:
        7 of them and filesize < 4553728
}