rule win_biscuit_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.biscuit."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.biscuit"
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
        $sequence_0 = { 84c0 7417 3cff 7413 85f6 7533 }
            // n = 6, score = 100
            //   84c0                 | test                al, al
            //   7417                 | je                  0x19
            //   3cff                 | cmp                 al, 0xff
            //   7413                 | je                  0x15
            //   85f6                 | test                esi, esi
            //   7533                 | jne                 0x35

        $sequence_1 = { 85c9 7409 83bddcbfffff00 7502 eb73 }
            // n = 5, score = 100
            //   85c9                 | test                ecx, ecx
            //   7409                 | je                  0xb
            //   83bddcbfffff00       | cmp                 dword ptr [ebp - 0x4024], 0
            //   7502                 | jne                 4
            //   eb73                 | jmp                 0x75

        $sequence_2 = { 6a00 6a00 ffd5 8b4304 8b08 }
            // n = 5, score = 100
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ffd5                 | call                ebp
            //   8b4304               | mov                 eax, dword ptr [ebx + 4]
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_3 = { 33c0 8dbdf0dfffff f3ab 83bde8bfffff00 762a c605????????01 6a00 }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   8dbdf0dfffff         | lea                 edi, [ebp - 0x2010]
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   83bde8bfffff00       | cmp                 dword ptr [ebp - 0x4018], 0
            //   762a                 | jbe                 0x2c
            //   c605????????01       |                     
            //   6a00                 | push                0

        $sequence_4 = { 50 51 ff15???????? 85c0 7507 bf???????? }
            // n = 6, score = 100
            //   50                   | push                eax
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7507                 | jne                 9
            //   bf????????           |                     

        $sequence_5 = { 8bca 50 83e103 f3a4 8d8b80000000 e8???????? e9???????? }
            // n = 7, score = 100
            //   8bca                 | mov                 ecx, edx
            //   50                   | push                eax
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8d8b80000000         | lea                 ecx, [ebx + 0x80]
            //   e8????????           |                     
            //   e9????????           |                     

        $sequence_6 = { 83bd18b7ffff00 0f856a050000 b980000000 33c0 8dbd40fdffff f3ab 8b4de0 }
            // n = 7, score = 100
            //   83bd18b7ffff00       | cmp                 dword ptr [ebp - 0x48e8], 0
            //   0f856a050000         | jne                 0x570
            //   b980000000           | mov                 ecx, 0x80
            //   33c0                 | xor                 eax, eax
            //   8dbd40fdffff         | lea                 edi, [ebp - 0x2c0]
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]

        $sequence_7 = { 50 6a00 ff15???????? 85c0 894634 0f85cb000000 bf???????? }
            // n = 7, score = 100
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   894634               | mov                 dword ptr [esi + 0x34], eax
            //   0f85cb000000         | jne                 0xd1
            //   bf????????           |                     

        $sequence_8 = { 8a11 80ea01 8b8528b6ffff 8810 c78530fdffff00000000 }
            // n = 5, score = 100
            //   8a11                 | mov                 dl, byte ptr [ecx]
            //   80ea01               | sub                 dl, 1
            //   8b8528b6ffff         | mov                 eax, dword ptr [ebp - 0x49d8]
            //   8810                 | mov                 byte ptr [eax], dl
            //   c78530fdffff00000000     | mov    dword ptr [ebp - 0x2d0], 0

        $sequence_9 = { f3ab 8b4c2418 51 68???????? 56 e8???????? }
            // n = 6, score = 100
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]
            //   51                   | push                ecx
            //   68????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     

    condition:
        7 of them and filesize < 180224
}