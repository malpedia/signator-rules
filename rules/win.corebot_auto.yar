rule win_corebot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.corebot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.corebot"
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
        $sequence_0 = { c7460400000000 8b06 85c0 7409 6a00 }
            // n = 5, score = 1100
            //   c7460400000000       | mov                 dword ptr [esi + 4], 0
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   85c0                 | test                eax, eax
            //   7409                 | je                  0xb
            //   6a00                 | push                0

        $sequence_1 = { 31c0 5e 5d c20800 55 89e5 }
            // n = 6, score = 1100
            //   31c0                 | xor                 eax, eax
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   c20800               | ret                 8
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp

        $sequence_2 = { 7410 89f1 e8???????? 56 e8???????? 83c404 }
            // n = 6, score = 1100
            //   7410                 | je                  0x12
            //   89f1                 | mov                 ecx, esi
            //   e8????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_3 = { 31f6 46 8918 89f0 83c40c 5e }
            // n = 6, score = 1100
            //   31f6                 | xor                 esi, esi
            //   46                   | inc                 esi
            //   8918                 | mov                 dword ptr [eax], ebx
            //   89f0                 | mov                 eax, esi
            //   83c40c               | add                 esp, 0xc
            //   5e                   | pop                 esi

        $sequence_4 = { 8b55e8 eb2c 8b45dc 8d48ff 85c0 894ddc }
            // n = 6, score = 1100
            //   8b55e8               | mov                 edx, dword ptr [ebp - 0x18]
            //   eb2c                 | jmp                 0x2e
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   8d48ff               | lea                 ecx, [eax - 1]
            //   85c0                 | test                eax, eax
            //   894ddc               | mov                 dword ptr [ebp - 0x24], ecx

        $sequence_5 = { ff15???????? 85c0 7418 8b0e 6a00 ff750c }
            // n = 6, score = 1100
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7418                 | je                  0x1a
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   6a00                 | push                0
            //   ff750c               | push                dword ptr [ebp + 0xc]

        $sequence_6 = { 8d4801 894dd8 b907000000 0fb610 8955e8 c745ec07000000 8d0412 }
            // n = 7, score = 1100
            //   8d4801               | lea                 ecx, [eax + 1]
            //   894dd8               | mov                 dword ptr [ebp - 0x28], ecx
            //   b907000000           | mov                 ecx, 7
            //   0fb610               | movzx               edx, byte ptr [eax]
            //   8955e8               | mov                 dword ptr [ebp - 0x18], edx
            //   c745ec07000000       | mov                 dword ptr [ebp - 0x14], 7
            //   8d0412               | lea                 eax, [edx + edx]

        $sequence_7 = { 8035????????e3 8035????????e4 8035????????e5 8035????????e6 }
            // n = 4, score = 1100
            //   8035????????e3       |                     
            //   8035????????e4       |                     
            //   8035????????e5       |                     
            //   8035????????e6       |                     

        $sequence_8 = { eb10 6800800000 6a00 56 ff15???????? }
            // n = 5, score = 1000
            //   eb10                 | jmp                 0x12
            //   6800800000           | push                0x8000
            //   6a00                 | push                0
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_9 = { ff15???????? 807e5000 7509 ff764c }
            // n = 4, score = 1000
            //   ff15????????         |                     
            //   807e5000             | cmp                 byte ptr [esi + 0x50], 0
            //   7509                 | jne                 0xb
            //   ff764c               | push                dword ptr [esi + 0x4c]

        $sequence_10 = { 85c0 7515 8b4624 3b4620 }
            // n = 4, score = 1000
            //   85c0                 | test                eax, eax
            //   7515                 | jne                 0x17
            //   8b4624               | mov                 eax, dword ptr [esi + 0x24]
            //   3b4620               | cmp                 eax, dword ptr [esi + 0x20]

        $sequence_11 = { 85ff 740f 57 ff7508 }
            // n = 4, score = 1000
            //   85ff                 | test                edi, edi
            //   740f                 | je                  0x11
            //   57                   | push                edi
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_12 = { 807e5800 7509 ff7654 ff15???????? }
            // n = 4, score = 1000
            //   807e5800             | cmp                 byte ptr [esi + 0x58], 0
            //   7509                 | jne                 0xb
            //   ff7654               | push                dword ptr [esi + 0x54]
            //   ff15????????         |                     

        $sequence_13 = { ff7010 ff7014 e8???????? 8b45e0 }
            // n = 4, score = 1000
            //   ff7010               | push                dword ptr [eax + 0x10]
            //   ff7014               | push                dword ptr [eax + 0x14]
            //   e8????????           |                     
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]

        $sequence_14 = { ff764c ff15???????? 8d4634 50 ff15???????? 8d4e0c }
            // n = 6, score = 1000
            //   ff764c               | push                dword ptr [esi + 0x4c]
            //   ff15????????         |                     
            //   8d4634               | lea                 eax, [esi + 0x34]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d4e0c               | lea                 ecx, [esi + 0xc]

        $sequence_15 = { ff742428 e8???????? 8b442424 8d4c2410 }
            // n = 4, score = 1000
            //   ff742428             | push                dword ptr [esp + 0x28]
            //   e8????????           |                     
            //   8b442424             | mov                 eax, dword ptr [esp + 0x24]
            //   8d4c2410             | lea                 ecx, [esp + 0x10]

    condition:
        7 of them and filesize < 1302528
}