rule win_enfal_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.enfal."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.enfal"
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
        $sequence_0 = { 894108 ffd6 8b4b1c 68???????? 57 89410c ffd6 }
            // n = 7, score = 200
            //   894108               | mov                 dword ptr [ecx + 8], eax
            //   ffd6                 | call                esi
            //   8b4b1c               | mov                 ecx, dword ptr [ebx + 0x1c]
            //   68????????           |                     
            //   57                   | push                edi
            //   89410c               | mov                 dword ptr [ecx + 0xc], eax
            //   ffd6                 | call                esi

        $sequence_1 = { 7405 6a6f 5f eb71 807dda01 7507 bf62020000 }
            // n = 7, score = 200
            //   7405                 | je                  7
            //   6a6f                 | push                0x6f
            //   5f                   | pop                 edi
            //   eb71                 | jmp                 0x73
            //   807dda01             | cmp                 byte ptr [ebp - 0x26], 1
            //   7507                 | jne                 9
            //   bf62020000           | mov                 edi, 0x262

        $sequence_2 = { 50 e8???????? be80000000 8d8568ffffff }
            // n = 4, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   be80000000           | mov                 esi, 0x80
            //   8d8568ffffff         | lea                 eax, [ebp - 0x98]

        $sequence_3 = { 50 e8???????? 83c410 8b461c }
            // n = 4, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8b461c               | mov                 eax, dword ptr [esi + 0x1c]

        $sequence_4 = { 8b7508 8d45e4 57 50 6a00 6a01 ff7608 }
            // n = 7, score = 200
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   57                   | push                edi
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   ff7608               | push                dword ptr [esi + 8]

        $sequence_5 = { 7410 8bd7 2bd0 880c02 8a4801 }
            // n = 5, score = 200
            //   7410                 | je                  0x12
            //   8bd7                 | mov                 edx, edi
            //   2bd0                 | sub                 edx, eax
            //   880c02               | mov                 byte ptr [edx + eax], cl
            //   8a4801               | mov                 cl, byte ptr [eax + 1]

        $sequence_6 = { ff15???????? 6a2f bf???????? 6a4c 57 e8???????? }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   6a2f                 | push                0x2f
            //   bf????????           |                     
            //   6a4c                 | push                0x4c
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_7 = { 59 8b560c 8b4e04 8a0438 0faf4d08 3a0411 }
            // n = 6, score = 200
            //   59                   | pop                 ecx
            //   8b560c               | mov                 edx, dword ptr [esi + 0xc]
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   8a0438               | mov                 al, byte ptr [eax + edi]
            //   0faf4d08             | imul                ecx, dword ptr [ebp + 8]
            //   3a0411               | cmp                 al, byte ptr [ecx + edx]

        $sequence_8 = { 57 68???????? e8???????? 33ff 6880000000 }
            // n = 5, score = 200
            //   57                   | push                edi
            //   68????????           |                     
            //   e8????????           |                     
            //   33ff                 | xor                 edi, edi
            //   6880000000           | push                0x80

        $sequence_9 = { ffd3 ff45e8 8345e404 397de8 0f8c21ffffff e9???????? }
            // n = 6, score = 200
            //   ffd3                 | call                ebx
            //   ff45e8               | inc                 dword ptr [ebp - 0x18]
            //   8345e404             | add                 dword ptr [ebp - 0x1c], 4
            //   397de8               | cmp                 dword ptr [ebp - 0x18], edi
            //   0f8c21ffffff         | jl                  0xffffff27
            //   e9????????           |                     

    condition:
        7 of them and filesize < 65536
}