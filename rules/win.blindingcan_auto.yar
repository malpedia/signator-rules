rule win_blindingcan_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.blindingcan."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blindingcan"
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
        $sequence_0 = { 55 8bec 83ec0c 8a8800010000 53 }
            // n = 5, score = 300
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec0c               | sub                 esp, 0xc
            //   8a8800010000         | mov                 cl, byte ptr [eax + 0x100]
            //   53                   | push                ebx

        $sequence_1 = { c745e484d9e35c c745e8a9840ef6 c745ec0d06092a c745f0864886f7 c745f40d010101 c745f805000382 e8???????? }
            // n = 7, score = 300
            //   c745e484d9e35c       | mov                 dword ptr [ebp - 0x1c], 0x5ce3d984
            //   c745e8a9840ef6       | mov                 dword ptr [ebp - 0x18], 0xf60e84a9
            //   c745ec0d06092a       | mov                 dword ptr [ebp - 0x14], 0x2a09060d
            //   c745f0864886f7       | mov                 dword ptr [ebp - 0x10], 0xf7864886
            //   c745f40d010101       | mov                 dword ptr [ebp - 0xc], 0x101010d
            //   c745f805000382       | mov                 dword ptr [ebp - 8], 0x82030005
            //   e8????????           |                     

        $sequence_2 = { ff15???????? 50 68???????? b900010000 }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   50                   | push                eax
            //   68????????           |                     
            //   b900010000           | mov                 ecx, 0x100

        $sequence_3 = { c785e8fcffffccc9d015 c785ecfcffff529bba20 c785f0fcffffb219e08f c785f4fcffff7939d39d c785f8fcffffe25fcedf c785fcfcfffff15112b2 }
            // n = 6, score = 300
            //   c785e8fcffffccc9d015     | mov    dword ptr [ebp - 0x318], 0x15d0c9cc
            //   c785ecfcffff529bba20     | mov    dword ptr [ebp - 0x314], 0x20ba9b52
            //   c785f0fcffffb219e08f     | mov    dword ptr [ebp - 0x310], 0x8fe019b2
            //   c785f4fcffff7939d39d     | mov    dword ptr [ebp - 0x30c], 0x9dd33979
            //   c785f8fcffffe25fcedf     | mov    dword ptr [ebp - 0x308], 0xdfce5fe2
            //   c785fcfcfffff15112b2     | mov    dword ptr [ebp - 0x304], 0xb21251f1

        $sequence_4 = { c78500feffff88551230 c78504feffff51456b07 c78508feffff788f2ba1 c7850cfeffff02c729c1 c78510feffffe7d792f3 c78514feffff91323bf3 }
            // n = 6, score = 300
            //   c78500feffff88551230     | mov    dword ptr [ebp - 0x200], 0x30125588
            //   c78504feffff51456b07     | mov    dword ptr [ebp - 0x1fc], 0x76b4551
            //   c78508feffff788f2ba1     | mov    dword ptr [ebp - 0x1f8], 0xa12b8f78
            //   c7850cfeffff02c729c1     | mov    dword ptr [ebp - 0x1f4], 0xc129c702
            //   c78510feffffe7d792f3     | mov    dword ptr [ebp - 0x1f0], 0xf392d7e7
            //   c78514feffff91323bf3     | mov    dword ptr [ebp - 0x1ec], 0xf33b3291

        $sequence_5 = { c785c8feffff1ce6ae9e c785ccfeffff64ceb0a1 c785d0feffff2d58cb71 c785d4feffff62c2f218 c785d8feffffcbdb9298 }
            // n = 5, score = 300
            //   c785c8feffff1ce6ae9e     | mov    dword ptr [ebp - 0x138], 0x9eaee61c
            //   c785ccfeffff64ceb0a1     | mov    dword ptr [ebp - 0x134], 0xa1b0ce64
            //   c785d0feffff2d58cb71     | mov    dword ptr [ebp - 0x130], 0x71cb582d
            //   c785d4feffff62c2f218     | mov    dword ptr [ebp - 0x12c], 0x18f2c262
            //   c785d8feffffcbdb9298     | mov    dword ptr [ebp - 0x128], 0x9892dbcb

        $sequence_6 = { c7459c52b86f28 c745a0b5c9a315 c745a453e8ba52 c745a8b67dbc8f c745ac3a39b69d }
            // n = 5, score = 300
            //   c7459c52b86f28       | mov                 dword ptr [ebp - 0x64], 0x286fb852
            //   c745a0b5c9a315       | mov                 dword ptr [ebp - 0x60], 0x15a3c9b5
            //   c745a453e8ba52       | mov                 dword ptr [ebp - 0x5c], 0x52bae853
            //   c745a8b67dbc8f       | mov                 dword ptr [ebp - 0x58], 0x8fbc7db6
            //   c745ac3a39b69d       | mov                 dword ptr [ebp - 0x54], 0x9db6393a

        $sequence_7 = { c7458cb6293481 c745902cab593c c74594a5337503 c745983e2c2bef c7459c506c3615 c745a07aea9b06 }
            // n = 6, score = 300
            //   c7458cb6293481       | mov                 dword ptr [ebp - 0x74], 0x813429b6
            //   c745902cab593c       | mov                 dword ptr [ebp - 0x70], 0x3c59ab2c
            //   c74594a5337503       | mov                 dword ptr [ebp - 0x6c], 0x37533a5
            //   c745983e2c2bef       | mov                 dword ptr [ebp - 0x68], 0xef2b2c3e
            //   c7459c506c3615       | mov                 dword ptr [ebp - 0x64], 0x15366c50
            //   c745a07aea9b06       | mov                 dword ptr [ebp - 0x60], 0x69bea7a

        $sequence_8 = { f7fe 8bca e8???????? 85c0 }
            // n = 4, score = 200
            //   f7fe                 | idiv                esi
            //   8bca                 | mov                 ecx, edx
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_9 = { 410fb6c0 41c1e818 33b48d10c70100 410fb6c8 33b48510cb0100 448ba48d10bf0100 410fb6c1 }
            // n = 7, score = 100
            //   410fb6c0             | movzx               eax, dl
            //   41c1e818             | inc                 ebp
            //   33b48d10c70100       | xor                 eax, dword ptr [esp + eax*4 + 0x1c310]
            //   410fb6c8             | inc                 ebp
            //   33b48510cb0100       | xor                 ecx, dword ptr [ebp - 8]
            //   448ba48d10bf0100     | movzx               eax, bl
            //   410fb6c1             | inc                 ecx

        $sequence_10 = { 488d14c8 420fbe940af0900100 c1fa04 89542460 8bca 85d2 0f8451070000 }
            // n = 7, score = 100
            //   488d14c8             | movzx               eax, al
            //   420fbe940af0900100     | inc    ecx
            //   c1fa04               | shr                 eax, 0x18
            //   89542460             | xor                 esi, dword ptr [ebp + ecx*4 + 0x1c710]
            //   8bca                 | inc                 ecx
            //   85d2                 | movzx               ecx, al
            //   0f8451070000         | xor                 esi, dword ptr [ebp + eax*4 + 0x1cb10]

        $sequence_11 = { 4981c590000000 45338c8410cb0100 458b848c10bf0100 410fb6c2 4533848410c30100 45334df8 0fb6c3 }
            // n = 7, score = 100
            //   4981c590000000       | dec                 ecx
            //   45338c8410cb0100     | add                 ebp, 0x90
            //   458b848c10bf0100     | inc                 ebp
            //   410fb6c2             | xor                 ecx, dword ptr [esp + eax*4 + 0x1cb10]
            //   4533848410c30100     | inc                 ebp
            //   45334df8             | mov                 eax, dword ptr [esp + ecx*4 + 0x1bf10]
            //   0fb6c3               | inc                 ecx

        $sequence_12 = { ff15???????? 4c8be0 4885c0 746e 4c8d442438 8d5308 488bc8 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   4c8be0               | mov                 dword ptr [esp + 0x60], edx
            //   4885c0               | mov                 ecx, edx
            //   746e                 | test                edx, edx
            //   4c8d442438           | je                  0x76b
            //   8d5308               | mov                 eax, ebx
            //   488bc8               | dec                 eax

        $sequence_13 = { ff15???????? 8bc3 488b8d80030000 4833cc e8???????? 4c8d9c2490040000 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   8bc3                 | inc                 esp
            //   488b8d80030000       | mov                 esp, dword ptr [ebp + ecx*4 + 0x1bf10]
            //   4833cc               | inc                 ecx
            //   e8????????           |                     
            //   4c8d9c2490040000     | movzx               eax, cl

        $sequence_14 = { 486bc958 48030cc2 eb07 488d0db7d40000 f6410820 7417 33d2 }
            // n = 7, score = 100
            //   486bc958             | mov                 ecx, dword ptr [ebp + 0x380]
            //   48030cc2             | dec                 eax
            //   eb07                 | xor                 ecx, esp
            //   488d0db7d40000       | dec                 esp
            //   f6410820             | lea                 ebx, [esp + 0x490]
            //   7417                 | inc                 eax
            //   33d2                 | dec                 eax

        $sequence_15 = { ffc0 4898 488d3c43 ff15???????? 488d8d60120000 bbfe030000 }
            // n = 6, score = 100
            //   ffc0                 | dec                 eax
            //   4898                 | lea                 edx, [eax + ecx*8]
            //   488d3c43             | inc                 edx
            //   ff15????????         |                     
            //   488d8d60120000       | movsx               edx, byte ptr [edx + ecx + 0x190f0]
            //   bbfe030000           | sar                 edx, 4

    condition:
        7 of them and filesize < 363520
}