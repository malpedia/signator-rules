rule win_corebot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.corebot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.corebot"
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
        $sequence_0 = { 0f95c0 eb08 c70600000000 31c0 5e 5d }
            // n = 6, score = 1100
            //   0f95c0               | setne               al
            //   eb08                 | jmp                 0xa
            //   c70600000000         | mov                 dword ptr [esi], 0
            //   31c0                 | xor                 eax, eax
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp

        $sequence_1 = { ff7508 51 ff15???????? 85c0 0f95c0 eb08 }
            // n = 6, score = 1100
            //   ff7508               | push                dword ptr [ebp + 8]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f95c0               | setne               al
            //   eb08                 | jmp                 0xa

        $sequence_2 = { 83c604 31c9 56 51 }
            // n = 4, score = 1100
            //   83c604               | add                 esi, 4
            //   31c9                 | xor                 ecx, ecx
            //   56                   | push                esi
            //   51                   | push                ecx

        $sequence_3 = { 31c0 85c9 8d49ff 751d 85db 8d5bff }
            // n = 6, score = 1100
            //   31c0                 | xor                 eax, eax
            //   85c9                 | test                ecx, ecx
            //   8d49ff               | lea                 ecx, [ecx - 1]
            //   751d                 | jne                 0x1f
            //   85db                 | test                ebx, ebx
            //   8d5bff               | lea                 ebx, [ebx - 1]

        $sequence_4 = { 8d4801 894dd8 0fb600 8945e8 c745ec07000000 8d1c00 }
            // n = 6, score = 1100
            //   8d4801               | lea                 ecx, [eax + 1]
            //   894dd8               | mov                 dword ptr [ebp - 0x28], ecx
            //   0fb600               | movzx               eax, byte ptr [eax]
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   c745ec07000000       | mov                 dword ptr [ebp - 0x14], 7
            //   8d1c00               | lea                 ebx, [eax + eax]

        $sequence_5 = { 31c0 40 8932 5e c3 31c0 ebfa }
            // n = 7, score = 1100
            //   31c0                 | xor                 eax, eax
            //   40                   | inc                 eax
            //   8932                 | mov                 dword ptr [edx], esi
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   31c0                 | xor                 eax, eax
            //   ebfa                 | jmp                 0xfffffffc

        $sequence_6 = { 89e5 56 8b31 85f6 7410 }
            // n = 5, score = 1100
            //   89e5                 | mov                 ebp, esp
            //   56                   | push                esi
            //   8b31                 | mov                 esi, dword ptr [ecx]
            //   85f6                 | test                esi, esi
            //   7410                 | je                  0x12

        $sequence_7 = { c7411407000000 8d4910 89c6 01c0 c1ee07 }
            // n = 5, score = 1100
            //   c7411407000000       | mov                 dword ptr [ecx + 0x14], 7
            //   8d4910               | lea                 ecx, [ecx + 0x10]
            //   89c6                 | mov                 esi, eax
            //   01c0                 | add                 eax, eax
            //   c1ee07               | shr                 esi, 7

        $sequence_8 = { eb10 6800800000 6a00 56 ff15???????? }
            // n = 5, score = 1000
            //   eb10                 | jmp                 0x12
            //   6800800000           | push                0x8000
            //   6a00                 | push                0
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_9 = { ff764c ff15???????? 8d4634 50 ff15???????? 8d4e0c }
            // n = 6, score = 1000
            //   ff764c               | push                dword ptr [esi + 0x4c]
            //   ff15????????         |                     
            //   8d4634               | lea                 eax, [esi + 0x34]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d4e0c               | lea                 ecx, [esi + 0xc]

        $sequence_10 = { ff742428 e8???????? 8b442424 8d4c2410 }
            // n = 4, score = 1000
            //   ff742428             | push                dword ptr [esp + 0x28]
            //   e8????????           |                     
            //   8b442424             | mov                 eax, dword ptr [esp + 0x24]
            //   8d4c2410             | lea                 ecx, [esp + 0x10]

        $sequence_11 = { ff7010 ff7014 e8???????? 8b45e0 }
            // n = 4, score = 1000
            //   ff7010               | push                dword ptr [eax + 0x10]
            //   ff7014               | push                dword ptr [eax + 0x14]
            //   e8????????           |                     
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]

        $sequence_12 = { ff15???????? 807e5000 7509 ff764c }
            // n = 4, score = 1000
            //   ff15????????         |                     
            //   807e5000             | cmp                 byte ptr [esi + 0x50], 0
            //   7509                 | jne                 0xb
            //   ff764c               | push                dword ptr [esi + 0x4c]

        $sequence_13 = { 807e5800 7509 ff7654 ff15???????? }
            // n = 4, score = 1000
            //   807e5800             | cmp                 byte ptr [esi + 0x58], 0
            //   7509                 | jne                 0xb
            //   ff7654               | push                dword ptr [esi + 0x54]
            //   ff15????????         |                     

        $sequence_14 = { 85ff 740f 57 ff7508 }
            // n = 4, score = 1000
            //   85ff                 | test                edi, edi
            //   740f                 | je                  0x11
            //   57                   | push                edi
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_15 = { 85c0 7515 8b4624 3b4620 }
            // n = 4, score = 1000
            //   85c0                 | test                eax, eax
            //   7515                 | jne                 0x17
            //   8b4624               | mov                 eax, dword ptr [esi + 0x24]
            //   3b4620               | cmp                 eax, dword ptr [esi + 0x20]

    condition:
        7 of them and filesize < 1302528
}