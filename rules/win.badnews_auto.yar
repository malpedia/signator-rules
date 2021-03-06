rule win_badnews_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.badnews."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.badnews"
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
        $sequence_0 = { 50 e8???????? 83c404 68???????? 6804010000 ff15???????? }
            // n = 6, score = 1000
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   68????????           |                     
            //   6804010000           | push                0x104
            //   ff15????????         |                     

        $sequence_1 = { eb02 33c9 c0e004 02c1 3423 c0c003 }
            // n = 6, score = 900
            //   eb02                 | jmp                 4
            //   33c9                 | xor                 ecx, ecx
            //   c0e004               | shl                 al, 4
            //   02c1                 | add                 al, cl
            //   3423                 | xor                 al, 0x23
            //   c0c003               | rol                 al, 3

        $sequence_2 = { c705????????33322e64 66c705????????6c6c c605????????00 ff15???????? }
            // n = 4, score = 900
            //   c705????????33322e64     |     
            //   66c705????????6c6c     |     
            //   c605????????00       |                     
            //   ff15????????         |                     

        $sequence_3 = { c78534ffffff47657457 c78538ffffff696e646f c7853cffffff77546578 66c78540ffffff7457 }
            // n = 4, score = 900
            //   c78534ffffff47657457     | mov    dword ptr [ebp - 0xcc], 0x57746547
            //   c78538ffffff696e646f     | mov    dword ptr [ebp - 0xc8], 0x6f646e69
            //   c7853cffffff77546578     | mov    dword ptr [ebp - 0xc4], 0x78655477
            //   66c78540ffffff7457     | mov    word ptr [ebp - 0xc0], 0x5774

        $sequence_4 = { 55 8bec 8b450c 3d01020000 }
            // n = 4, score = 900
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   3d01020000           | cmp                 eax, 0x201

        $sequence_5 = { 8945fc 53 56 57 8d8534ffffff }
            // n = 5, score = 900
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8d8534ffffff         | lea                 eax, [ebp - 0xcc]

        $sequence_6 = { 6a00 d1f9 68???????? 03c9 }
            // n = 4, score = 800
            //   6a00                 | push                0
            //   d1f9                 | sar                 ecx, 1
            //   68????????           |                     
            //   03c9                 | add                 ecx, ecx

        $sequence_7 = { 68???????? 6a1a 68???????? 57 }
            // n = 4, score = 800
            //   68????????           |                     
            //   6a1a                 | push                0x1a
            //   68????????           |                     
            //   57                   | push                edi

        $sequence_8 = { ffd3 85c0 7403 83c608 }
            // n = 4, score = 700
            //   ffd3                 | call                ebx
            //   85c0                 | test                eax, eax
            //   7403                 | je                  5
            //   83c608               | add                 esi, 8

        $sequence_9 = { 8bf0 56 ff15???????? 50 6a40 }
            // n = 5, score = 700
            //   8bf0                 | mov                 esi, eax
            //   56                   | push                esi
            //   ff15????????         |                     
            //   50                   | push                eax
            //   6a40                 | push                0x40

        $sequence_10 = { 57 6a00 6880000000 6a04 6a00 6a01 6a04 }
            // n = 7, score = 700
            //   57                   | push                edi
            //   6a00                 | push                0
            //   6880000000           | push                0x80
            //   6a04                 | push                4
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   6a04                 | push                4

        $sequence_11 = { ff15???????? 85c0 7405 83c004 }
            // n = 4, score = 700
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7405                 | je                  7
            //   83c004               | add                 eax, 4

        $sequence_12 = { 68???????? ff15???????? b8???????? 83c424 }
            // n = 4, score = 500
            //   68????????           |                     
            //   ff15????????         |                     
            //   b8????????           |                     
            //   83c424               | add                 esp, 0x24

        $sequence_13 = { 8b8528e5ffff 8b0485d0a70110 89853ce5ffff 397c0138 741c 8a440134 }
            // n = 6, score = 100
            //   8b8528e5ffff         | mov                 eax, dword ptr [ebp - 0x1ad8]
            //   8b0485d0a70110       | mov                 eax, dword ptr [eax*4 + 0x1001a7d0]
            //   89853ce5ffff         | mov                 dword ptr [ebp - 0x1ac4], eax
            //   397c0138             | cmp                 dword ptr [ecx + eax + 0x38], edi
            //   741c                 | je                  0x1e
            //   8a440134             | mov                 al, byte ptr [ecx + eax + 0x34]

        $sequence_14 = { c1f805 c1e606 8b0485d0a70110 80643004fd 8b45f8 8b55fc }
            // n = 6, score = 100
            //   c1f805               | sar                 eax, 5
            //   c1e606               | shl                 esi, 6
            //   8b0485d0a70110       | mov                 eax, dword ptr [eax*4 + 0x1001a7d0]
            //   80643004fd           | and                 byte ptr [eax + esi + 4], 0xfd
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]

        $sequence_15 = { 47 84c0 75f8 eb7c 68???????? e8???????? }
            // n = 6, score = 100
            //   47                   | inc                 edi
            //   84c0                 | test                al, al
            //   75f8                 | jne                 0xfffffffa
            //   eb7c                 | jmp                 0x7e
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_16 = { 75e8 eb64 a1???????? 8b9c9d58fbffff 8945f0 66a1???????? }
            // n = 6, score = 100
            //   75e8                 | jne                 0xffffffea
            //   eb64                 | jmp                 0x66
            //   a1????????           |                     
            //   8b9c9d58fbffff       | mov                 ebx, dword ptr [ebp + ebx*4 - 0x4a8]
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   66a1????????         |                     

        $sequence_17 = { 59 59 8bc8 894de0 85c9 7465 890c9dd0a70110 }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   8bc8                 | mov                 ecx, eax
            //   894de0               | mov                 dword ptr [ebp - 0x20], ecx
            //   85c9                 | test                ecx, ecx
            //   7465                 | je                  0x67
            //   890c9dd0a70110       | mov                 dword ptr [ebx*4 + 0x1001a7d0], ecx

        $sequence_18 = { 57 8a4c0df0 32c8 80e907 }
            // n = 4, score = 100
            //   57                   | push                edi
            //   8a4c0df0             | mov                 cl, byte ptr [ebp + ecx - 0x10]
            //   32c8                 | xor                 cl, al
            //   80e907               | sub                 cl, 7

        $sequence_19 = { 8b0485d0a70110 0fbe441804 83e001 7470 57 e8???????? 59 }
            // n = 7, score = 100
            //   8b0485d0a70110       | mov                 eax, dword ptr [eax*4 + 0x1001a7d0]
            //   0fbe441804           | movsx               eax, byte ptr [eax + ebx + 4]
            //   83e001               | and                 eax, 1
            //   7470                 | je                  0x72
            //   57                   | push                edi
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_20 = { e8???????? 83c40c 4e 75e8 eb64 a1???????? }
            // n = 6, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   4e                   | dec                 esi
            //   75e8                 | jne                 0xffffffea
            //   eb64                 | jmp                 0x66
            //   a1????????           |                     

    condition:
        7 of them and filesize < 612352
}