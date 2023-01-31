rule win_nettraveler_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.nettraveler."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nettraveler"
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
        $sequence_0 = { 56 e8???????? 83c7f4 8d4607 57 50 }
            // n = 6, score = 100
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c7f4               | add                 edi, -0xc
            //   8d4607               | lea                 eax, [esi + 7]
            //   57                   | push                edi
            //   50                   | push                eax

        $sequence_1 = { e8???????? 8b45f4 83c414 83c002 33d2 6a03 be???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   83c414               | add                 esp, 0x14
            //   83c002               | add                 eax, 2
            //   33d2                 | xor                 edx, edx
            //   6a03                 | push                3
            //   be????????           |                     

        $sequence_2 = { 03c1 8b4df4 014604 8d45b4 }
            // n = 4, score = 100
            //   03c1                 | add                 eax, ecx
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   014604               | add                 dword ptr [esi + 4], eax
            //   8d45b4               | lea                 eax, [ebp - 0x4c]

        $sequence_3 = { 0bc3 0345cc 8d8c0140b340c0 8bc1 c1e817 }
            // n = 5, score = 100
            //   0bc3                 | or                  eax, ebx
            //   0345cc               | add                 eax, dword ptr [ebp - 0x34]
            //   8d8c0140b340c0       | lea                 ecx, [ecx + eax - 0x3fbf4cc0]
            //   8bc1                 | mov                 eax, ecx
            //   c1e817               | shr                 eax, 0x17

        $sequence_4 = { 8d45c8 50 53 53 68???????? ff75e4 ff15???????? }
            // n = 7, score = 100
            //   8d45c8               | lea                 eax, [ebp - 0x38]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   68????????           |                     
            //   ff75e4               | push                dword ptr [ebp - 0x1c]
            //   ff15????????         |                     

        $sequence_5 = { 7522 e8???????? 393d???????? 7410 e8???????? 85c0 7507 }
            // n = 7, score = 100
            //   7522                 | jne                 0x24
            //   e8????????           |                     
            //   393d????????         |                     
            //   7410                 | je                  0x12
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7507                 | jne                 9

        $sequence_6 = { 8b35???????? 895df8 895df0 bf00200000 395dfc 7519 57 }
            // n = 7, score = 100
            //   8b35????????         |                     
            //   895df8               | mov                 dword ptr [ebp - 8], ebx
            //   895df0               | mov                 dword ptr [ebp - 0x10], ebx
            //   bf00200000           | mov                 edi, 0x2000
            //   395dfc               | cmp                 dword ptr [ebp - 4], ebx
            //   7519                 | jne                 0x1b
            //   57                   | push                edi

        $sequence_7 = { ffd6 8d45f4 50 8d85b4feffff }
            // n = 4, score = 100
            //   ffd6                 | call                esi
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   8d85b4feffff         | lea                 eax, [ebp - 0x14c]

        $sequence_8 = { 50 ff15???????? 8b1d???????? 8bf8 57 6a08 ffd3 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b1d????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   57                   | push                edi
            //   6a08                 | push                8
            //   ffd3                 | call                ebx

        $sequence_9 = { 8b35???????? 57 68???????? 8d85c8feffff }
            // n = 4, score = 100
            //   8b35????????         |                     
            //   57                   | push                edi
            //   68????????           |                     
            //   8d85c8feffff         | lea                 eax, [ebp - 0x138]

    condition:
        7 of them and filesize < 106496
}