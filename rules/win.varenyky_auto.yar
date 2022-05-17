rule win_varenyky_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.varenyky."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.varenyky"
        malpedia_rule_date = "20220513"
        malpedia_hash = "7f4b2229e6ae614d86d74917f6d5b41890e62a26"
        malpedia_version = "20220516"
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
        $sequence_0 = { 8bff 56 57 33ff 8db760fc4000 ff36 e8???????? }
            // n = 7, score = 100
            //   8bff                 | mov                 edi, edi
            //   56                   | push                esi
            //   57                   | push                edi
            //   33ff                 | xor                 edi, edi
            //   8db760fc4000         | lea                 esi, [edi + 0x40fc60]
            //   ff36                 | push                dword ptr [esi]
            //   e8????????           |                     

        $sequence_1 = { 53 8db42484010000 e8???????? 83c40c }
            // n = 4, score = 100
            //   53                   | push                ebx
            //   8db42484010000       | lea                 esi, [esp + 0x184]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_2 = { 68???????? 33ff 52 897c2418 e8???????? 83c408 3bc7 }
            // n = 7, score = 100
            //   68????????           |                     
            //   33ff                 | xor                 edi, edi
            //   52                   | push                edx
            //   897c2418             | mov                 dword ptr [esp + 0x18], edi
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   3bc7                 | cmp                 eax, edi

        $sequence_3 = { 8bf8 33d2 8bc1 f7f7 41 8a142a 30940c4f040000 }
            // n = 7, score = 100
            //   8bf8                 | mov                 edi, eax
            //   33d2                 | xor                 edx, edx
            //   8bc1                 | mov                 eax, ecx
            //   f7f7                 | div                 edi
            //   41                   | inc                 ecx
            //   8a142a               | mov                 dl, byte ptr [edx + ebp]
            //   30940c4f040000       | xor                 byte ptr [esp + ecx + 0x44f], dl

        $sequence_4 = { 7427 83c010 803800 8bc8 740e }
            // n = 5, score = 100
            //   7427                 | je                  0x29
            //   83c010               | add                 eax, 0x10
            //   803800               | cmp                 byte ptr [eax], 0
            //   8bc8                 | mov                 ecx, eax
            //   740e                 | je                  0x10

        $sequence_5 = { 89442434 89442438 8d842490010000 50 6a00 c744243400000000 c744244844000000 }
            // n = 7, score = 100
            //   89442434             | mov                 dword ptr [esp + 0x34], eax
            //   89442438             | mov                 dword ptr [esp + 0x38], eax
            //   8d842490010000       | lea                 eax, [esp + 0x190]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   c744243400000000     | mov                 dword ptr [esp + 0x34], 0
            //   c744244844000000     | mov                 dword ptr [esp + 0x48], 0x44

        $sequence_6 = { 6a01 8d542417 52 55 ffd7 85c0 }
            // n = 6, score = 100
            //   6a01                 | push                1
            //   8d542417             | lea                 edx, [esp + 0x17]
            //   52                   | push                edx
            //   55                   | push                ebp
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax

        $sequence_7 = { 83feff 746a 57 ff15???????? }
            // n = 4, score = 100
            //   83feff               | cmp                 esi, -1
            //   746a                 | je                  0x6c
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_8 = { 8944242c 89442434 89442438 8944243c 89442440 c744243001000000 c744242850000000 }
            // n = 7, score = 100
            //   8944242c             | mov                 dword ptr [esp + 0x2c], eax
            //   89442434             | mov                 dword ptr [esp + 0x34], eax
            //   89442438             | mov                 dword ptr [esp + 0x38], eax
            //   8944243c             | mov                 dword ptr [esp + 0x3c], eax
            //   89442440             | mov                 dword ptr [esp + 0x40], eax
            //   c744243001000000     | mov                 dword ptr [esp + 0x30], 1
            //   c744242850000000     | mov                 dword ptr [esp + 0x28], 0x50

        $sequence_9 = { 85c0 0f8e45020000 0fb74b08 51 ff15???????? }
            // n = 5, score = 100
            //   85c0                 | test                eax, eax
            //   0f8e45020000         | jle                 0x24b
            //   0fb74b08             | movzx               ecx, word ptr [ebx + 8]
            //   51                   | push                ecx
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 24846336
}