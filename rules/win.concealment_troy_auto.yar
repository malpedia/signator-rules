rule win_concealment_troy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.concealment_troy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.concealment_troy"
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
        $sequence_0 = { 7569 8b44240c 50 ff15???????? 53 }
            // n = 5, score = 100
            //   7569                 | jne                 0x6b
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   53                   | push                ebx

        $sequence_1 = { 51 e8???????? 8d442428 83c40c }
            // n = 4, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8d442428             | lea                 eax, [esp + 0x28]
            //   83c40c               | add                 esp, 0xc

        $sequence_2 = { 85c0 752c 57 ff15???????? 53 ff15???????? 56 }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   752c                 | jne                 0x2e
            //   57                   | push                edi
            //   ff15????????         |                     
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   56                   | push                esi

        $sequence_3 = { e8???????? 59 897dfc 897dd8 83ff40 0f8d3c010000 8b34bda0774100 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   897dd8               | mov                 dword ptr [ebp - 0x28], edi
            //   83ff40               | cmp                 edi, 0x40
            //   0f8d3c010000         | jge                 0x142
            //   8b34bda0774100       | mov                 esi, dword ptr [edi*4 + 0x4177a0]

        $sequence_4 = { 8bd8 85db 751e 57 ff15???????? }
            // n = 5, score = 100
            //   8bd8                 | mov                 ebx, eax
            //   85db                 | test                ebx, ebx
            //   751e                 | jne                 0x20
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_5 = { c1f905 8b0c8da0774100 83e01f c1e006 8d440124 8a08 }
            // n = 6, score = 100
            //   c1f905               | sar                 ecx, 5
            //   8b0c8da0774100       | mov                 ecx, dword ptr [ecx*4 + 0x4177a0]
            //   83e01f               | and                 eax, 0x1f
            //   c1e006               | shl                 eax, 6
            //   8d440124             | lea                 eax, [ecx + eax + 0x24]
            //   8a08                 | mov                 cl, byte ptr [eax]

        $sequence_6 = { e8???????? 83c414 807c24104d 0f85b1000000 807c24115a 0f85a6000000 53 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   807c24104d           | cmp                 byte ptr [esp + 0x10], 0x4d
            //   0f85b1000000         | jne                 0xb7
            //   807c24115a           | cmp                 byte ptr [esp + 0x11], 0x5a
            //   0f85a6000000         | jne                 0xac
            //   53                   | push                ebx

        $sequence_7 = { 0f84ba000000 8975e0 8b04bda0774100 0500080000 3bf0 }
            // n = 5, score = 100
            //   0f84ba000000         | je                  0xc0
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi
            //   8b04bda0774100       | mov                 eax, dword ptr [edi*4 + 0x4177a0]
            //   0500080000           | add                 eax, 0x800
            //   3bf0                 | cmp                 esi, eax

        $sequence_8 = { 6800040000 8bf0 6a00 56 e8???????? 6808020000 8dbe00040000 }
            // n = 7, score = 100
            //   6800040000           | push                0x400
            //   8bf0                 | mov                 esi, eax
            //   6a00                 | push                0
            //   56                   | push                esi
            //   e8????????           |                     
            //   6808020000           | push                0x208
            //   8dbe00040000         | lea                 edi, [esi + 0x400]

        $sequence_9 = { 50 8d8c2438050000 6a01 51 e8???????? 56 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   8d8c2438050000       | lea                 ecx, [esp + 0x538]
            //   6a01                 | push                1
            //   51                   | push                ecx
            //   e8????????           |                     
            //   56                   | push                esi

    condition:
        7 of them and filesize < 229376
}