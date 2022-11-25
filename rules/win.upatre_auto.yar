rule win_upatre_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.upatre."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.upatre"
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
        $sequence_0 = { 84c0 75f4 ebed 33c0 ac 8975f8 c1e002 }
            // n = 7, score = 200
            //   84c0                 | test                al, al
            //   75f4                 | jne                 0xfffffff6
            //   ebed                 | jmp                 0xffffffef
            //   33c0                 | xor                 eax, eax
            //   ac                   | lodsb               al, byte ptr [esi]
            //   8975f8               | mov                 dword ptr [ebp - 8], esi
            //   c1e002               | shl                 eax, 2

        $sequence_1 = { 8945e8 6a00 8d4de0 51 ff75e8 }
            // n = 5, score = 200
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   6a00                 | push                0
            //   8d4de0               | lea                 ecx, [ebp - 0x20]
            //   51                   | push                ecx
            //   ff75e8               | push                dword ptr [ebp - 0x18]

        $sequence_2 = { 84c0 75fb ac fec8 740f fec8 7414 }
            // n = 7, score = 200
            //   84c0                 | test                al, al
            //   75fb                 | jne                 0xfffffffd
            // 
            //   fec8                 | dec                 al
            //   740f                 | je                  0x11
            //   fec8                 | dec                 al
            //   7414                 | je                  0x16

        $sequence_3 = { 740f fec8 7414 4e 56 ff75f0 ff55f8 }
            // n = 7, score = 200
            //   740f                 | je                  0x11
            //   fec8                 | dec                 al
            //   7414                 | je                  0x16
            //   4e                   | dec                 esi
            //   56                   | push                esi
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   ff55f8               | call                dword ptr [ebp - 8]

        $sequence_4 = { 33c9 66ad 6685c0 7404 }
            // n = 4, score = 200
            //   33c9                 | xor                 ecx, ecx
            //   66ad                 | lodsw               ax, word ptr [esi]
            //   6685c0               | test                ax, ax
            //   7404                 | je                  6

        $sequence_5 = { 7404 66ab ebf5 85c9 }
            // n = 4, score = 200
            //   7404                 | je                  6
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   ebf5                 | jmp                 0xfffffff7
            //   85c9                 | test                ecx, ecx

        $sequence_6 = { 81c60e010000 ac 3c01 740c }
            // n = 4, score = 200
            //   81c60e010000         | add                 esi, 0x10e
            //   ac                   | lodsb               al, byte ptr [esi]
            //   3c01                 | cmp                 al, 1
            //   740c                 | je                  0xe

        $sequence_7 = { 33c0 8bf8 57 6880000000 }
            // n = 4, score = 200
            //   33c0                 | xor                 eax, eax
            //   8bf8                 | mov                 edi, eax
            //   57                   | push                edi
            //   6880000000           | push                0x80

        $sequence_8 = { 7d51 8b4508 0345f0 0fbe08 8b5510 0faf55f8 }
            // n = 6, score = 100
            //   7d51                 | jge                 0x53
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   0345f0               | add                 eax, dword ptr [ebp - 0x10]
            //   0fbe08               | movsx               ecx, byte ptr [eax]
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   0faf55f8             | imul                edx, dword ptr [ebp - 8]

        $sequence_9 = { e8???????? 83c40c 8945d8 8b45d8 8b4808 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]
            //   8b4808               | mov                 ecx, dword ptr [eax + 8]

        $sequence_10 = { 4c 74f3 03bc7d1e23d4fa af }
            // n = 4, score = 100
            //   4c                   | dec                 esp
            //   74f3                 | je                  0xfffffff5
            //   03bc7d1e23d4fa       | add                 edi, dword ptr [ebp + edi*2 - 0x52bdce2]
            //   af                   | scasd               eax, dword ptr es:[edi]

        $sequence_11 = { 8d45f8 50 8b4d0c 2b4d08 51 8b5508 }
            // n = 6, score = 100
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   2b4d08               | sub                 ecx, dword ptr [ebp + 8]
            //   51                   | push                ecx
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]

        $sequence_12 = { 6a01 8d55c3 52 8b45fc 2b45c8 50 8b4dc8 }
            // n = 7, score = 100
            //   6a01                 | push                1
            //   8d55c3               | lea                 edx, [ebp - 0x3d]
            //   52                   | push                edx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   2b45c8               | sub                 eax, dword ptr [ebp - 0x38]
            //   50                   | push                eax
            //   8b4dc8               | mov                 ecx, dword ptr [ebp - 0x38]

        $sequence_13 = { 894df4 eb0e 8b55e8 0355ec 8955e8 }
            // n = 5, score = 100
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   eb0e                 | jmp                 0x10
            //   8b55e8               | mov                 edx, dword ptr [ebp - 0x18]
            //   0355ec               | add                 edx, dword ptr [ebp - 0x14]
            //   8955e8               | mov                 dword ptr [ebp - 0x18], edx

        $sequence_14 = { 83f905 7514 8b55f8 52 8b45fc 50 }
            // n = 6, score = 100
            //   83f905               | cmp                 ecx, 5
            //   7514                 | jne                 0x16
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   52                   | push                edx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax

        $sequence_15 = { 6800100000 6a00 e8???????? 8945d8 8b4508 }
            // n = 5, score = 100
            //   6800100000           | push                0x1000
            //   6a00                 | push                0
            //   e8????????           |                     
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

    condition:
        7 of them and filesize < 294912
}