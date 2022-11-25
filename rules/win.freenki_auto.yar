rule win_freenki_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.freenki."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.freenki"
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
        $sequence_0 = { 8d3c9db4354200 f00fb10f 8bc8 85c9 740b }
            // n = 5, score = 200
            //   8d3c9db4354200       | lea                 edi, [ebx*4 + 0x4235b4]
            //   f00fb10f             | lock cmpxchg        dword ptr [edi], ecx
            //   8bc8                 | mov                 ecx, eax
            //   85c9                 | test                ecx, ecx
            //   740b                 | je                  0xd

        $sequence_1 = { e8???????? 89461c 83f808 74ba 83f807 77c5 ff248595924000 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   89461c               | mov                 dword ptr [esi + 0x1c], eax
            //   83f808               | cmp                 eax, 8
            //   74ba                 | je                  0xffffffbc
            //   83f807               | cmp                 eax, 7
            //   77c5                 | ja                  0xffffffc7
            //   ff248595924000       | jmp                 dword ptr [eax*4 + 0x409295]

        $sequence_2 = { 7d4d 8b049d78394200 8945d8 85c0 7553 e8???????? 89049d78394200 }
            // n = 7, score = 200
            //   7d4d                 | jge                 0x4f
            //   8b049d78394200       | mov                 eax, dword ptr [ebx*4 + 0x423978]
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   85c0                 | test                eax, eax
            //   7553                 | jne                 0x55
            //   e8????????           |                     
            //   89049d78394200       | mov                 dword ptr [ebx*4 + 0x423978], eax

        $sequence_3 = { 50 8b45e4 6a00 6a30 56 52 }
            // n = 6, score = 200
            //   50                   | push                eax
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   6a00                 | push                0
            //   6a30                 | push                0x30
            //   56                   | push                esi
            //   52                   | push                edx

        $sequence_4 = { 85c0 0f8497000000 a1???????? 0f1005???????? 68f4010000 8985f8fdffff 8d85fcfdffff }
            // n = 7, score = 200
            //   85c0                 | test                eax, eax
            //   0f8497000000         | je                  0x9d
            //   a1????????           |                     
            //   0f1005????????       |                     
            //   68f4010000           | push                0x1f4
            //   8985f8fdffff         | mov                 dword ptr [ebp - 0x208], eax
            //   8d85fcfdffff         | lea                 eax, [ebp - 0x204]

        $sequence_5 = { 894df0 e8???????? 8bf8 83c404 85ff 0f84e4000000 6804010000 }
            // n = 7, score = 200
            //   894df0               | mov                 dword ptr [ebp - 0x10], ecx
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   83c404               | add                 esp, 4
            //   85ff                 | test                edi, edi
            //   0f84e4000000         | je                  0xea
            //   6804010000           | push                0x104

        $sequence_6 = { c745c000000000 c745c400000000 c745c800000000 ff15???????? 898554ffffff 57 85c0 }
            // n = 7, score = 200
            //   c745c000000000       | mov                 dword ptr [ebp - 0x40], 0
            //   c745c400000000       | mov                 dword ptr [ebp - 0x3c], 0
            //   c745c800000000       | mov                 dword ptr [ebp - 0x38], 0
            //   ff15????????         |                     
            //   898554ffffff         | mov                 dword ptr [ebp - 0xac], eax
            //   57                   | push                edi
            //   85c0                 | test                eax, eax

        $sequence_7 = { e8???????? 6aff 6a00 8d8540d4ffff }
            // n = 4, score = 200
            //   e8????????           |                     
            //   6aff                 | push                -1
            //   6a00                 | push                0
            //   8d8540d4ffff         | lea                 eax, [ebp - 0x2bc0]

        $sequence_8 = { 83c420 b8???????? b9???????? 660f1f440000 8a11 3a10 751a }
            // n = 7, score = 200
            //   83c420               | add                 esp, 0x20
            //   b8????????           |                     
            //   b9????????           |                     
            //   660f1f440000         | nop                 word ptr [eax + eax]
            //   8a11                 | mov                 dl, byte ptr [ecx]
            //   3a10                 | cmp                 dl, byte ptr [eax]
            //   751a                 | jne                 0x1c

        $sequence_9 = { 6bc930 8b048578394200 f644082801 7406 8b440818 5d c3 }
            // n = 7, score = 200
            //   6bc930               | imul                ecx, ecx, 0x30
            //   8b048578394200       | mov                 eax, dword ptr [eax*4 + 0x423978]
            //   f644082801           | test                byte ptr [eax + ecx + 0x28], 1
            //   7406                 | je                  8
            //   8b440818             | mov                 eax, dword ptr [eax + ecx + 0x18]
            //   5d                   | pop                 ebp
            //   c3                   | ret                 

    condition:
        7 of them and filesize < 327680
}