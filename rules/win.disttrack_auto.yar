rule win_disttrack_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.disttrack."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.disttrack"
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
        $sequence_0 = { 68???????? ff15???????? 8d45dc 50 ff15???????? 8b4ddc }
            // n = 6, score = 200
            //   68????????           |                     
            //   ff15????????         |                     
            //   8d45dc               | mov                 dword ptr [ecx], eax
            //   50                   | dec                 eax
            //   ff15????????         |                     
            //   8b4ddc               | cmp                 dword ptr [ecx + 0x98], 0

        $sequence_1 = { 52 6a00 6a00 6848000700 }
            // n = 4, score = 200
            //   52                   | mov                 ebx, ecx
            //   6a00                 | dec                 eax
            //   6a00                 | lea                 eax, [0x12ca2]
            //   6848000700           | dec                 eax

        $sequence_2 = { ebb2 6a16 58 5e 5d c3 6a0c }
            // n = 7, score = 200
            //   ebb2                 | jmp                 0xffffffb4
            //   6a16                 | push                0x16
            //   58                   | pop                 eax
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   6a0c                 | push                0xc

        $sequence_3 = { 83c404 50 e8???????? 83c404 68???????? ff15???????? e8???????? }
            // n = 7, score = 200
            //   83c404               | dec                 eax
            //   50                   | lea                 ecx, [ebp + 0x18]
            //   e8????????           |                     
            //   83c404               | dec                 esp
            //   68????????           |                     
            //   ff15????????         |                     
            //   e8????????           |                     

        $sequence_4 = { 57 e8???????? 6a07 e8???????? 59 c3 6a10 }
            // n = 7, score = 200
            //   57                   | push                edi
            //   e8????????           |                     
            //   6a07                 | push                7
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   6a10                 | push                0x10

        $sequence_5 = { ff15???????? 5d 5b 8bc7 5f 5e }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   5d                   | dec                 ecx
            //   5b                   | mov                 ecx, ebp
            //   8bc7                 | dec                 eax
            //   5f                   | lea                 edx, [ebp + eax*2 - 0x80]
            //   5e                   | nop                 

        $sequence_6 = { 488bf0 eb05 488b742478 448b442470 4c8d4c2470 }
            // n = 5, score = 100
            //   488bf0               | mov                 ecx, dword ptr [edi + ecx]
            //   eb05                 | sete                bl
            //   488b742478           | jmp                 4
            //   448b442470           | xor                 al, al
            //   4c8d4c2470           | dec                 esp

        $sequence_7 = { c7440c2cd42a4200 8b54243c 8b4204 c744043ccc2a4200 8b4c242c 8b5104 }
            // n = 6, score = 100
            //   c7440c2cd42a4200     | push                eax
            //   8b54243c             | add                 esp, 4
            //   8b4204               | push                ebx
            //   c744043ccc2a4200     | pop                 ebp
            //   8b4c242c             | pop                 ebx
            //   8b5104               | mov                 eax, edi

        $sequence_8 = { 498bd5 ff15???????? 4c8be0 4885c0 0f84f9000000 }
            // n = 5, score = 100
            //   498bd5               | cmp                 word ptr [ebp - 0x18], si
            //   ff15????????         |                     
            //   4c8be0               | dec                 ecx
            //   4885c0               | mov                 edx, ebp
            //   0f84f9000000         | dec                 esp

        $sequence_9 = { 7e04 32c0 eb48 8d5508 52 b9???????? }
            // n = 6, score = 100
            //   7e04                 | pop                 ebp
            //   32c0                 | pop                 ebx
            //   eb48                 | mov                 eax, edi
            //   8d5508               | pop                 edi
            //   52                   | pop                 esi
            //   b9????????           |                     

        $sequence_10 = { 8365d800 c745dc40754000 a1???????? 8d4dd8 33c1 8945e0 8b4518 }
            // n = 7, score = 100
            //   8365d800             | and                 dword ptr [ebp - 0x28], 0
            //   c745dc40754000       | mov                 dword ptr [ebp - 0x24], 0x407540
            //   a1????????           |                     
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   33c1                 | xor                 eax, ecx
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   8b4518               | mov                 eax, dword ptr [ebp + 0x18]

        $sequence_11 = { 488bd9 488d05a22c0100 488901 4883b99800000000 }
            // n = 4, score = 100
            //   488bd9               | inc                 esp
            //   488d05a22c0100       | mov                 eax, dword ptr [esp + 0x70]
            //   488901               | dec                 esp
            //   4883b99800000000     | lea                 ecx, [esp + 0x70]

        $sequence_12 = { 75fc eb0d ff15???????? 89459c 33c0 }
            // n = 5, score = 100
            //   75fc                 | add                 esp, 4
            //   eb0d                 | push                eax
            //   ff15????????         |                     
            //   89459c               | add                 esp, 4
            //   33c0                 | add                 esp, 4

        $sequence_13 = { c7443890d42a4200 8b4fa0 8b5104 c7443aa0cc2a4200 }
            // n = 4, score = 100
            //   c7443890d42a4200     | push                0x70048
            //   8b4fa0               | lea                 eax, [ebp - 0x24]
            //   8b5104               | push                eax
            //   c7443aa0cc2a4200     | mov                 ecx, dword ptr [ebp - 0x24]

        $sequence_14 = { 7216 66443965e6 720f 663975e8 }
            // n = 4, score = 100
            //   7216                 | jb                  0x18
            //   66443965e6           | inc                 sp
            //   720f                 | cmp                 dword ptr [ebp - 0x1a], esp
            //   663975e8             | jb                  0x11

        $sequence_15 = { 90 488d4d18 e8???????? 4c8d1d03230100 4c895d18 488d4d18 }
            // n = 6, score = 100
            //   90                   | dec                 eax
            //   488d4d18             | mov                 esi, eax
            //   e8????????           |                     
            //   4c8d1d03230100       | jmp                 0xa
            //   4c895d18             | dec                 eax
            //   488d4d18             | mov                 esi, dword ptr [esp + 0x78]

        $sequence_16 = { c1e106 030c9d40174200 eb02 8bca }
            // n = 4, score = 100
            //   c1e106               | shl                 ecx, 6
            //   030c9d40174200       | add                 ecx, dword ptr [ebx*4 + 0x421740]
            //   eb02                 | jmp                 4
            //   8bca                 | mov                 ecx, edx

        $sequence_17 = { 53 e8???????? 399c24a0000000 0f84af000000 }
            // n = 4, score = 100
            //   53                   | push                ebx
            //   e8????????           |                     
            //   399c24a0000000       | cmp                 dword ptr [esp + 0xa0], ebx
            //   0f84af000000         | je                  0xb5

        $sequence_18 = { 488d0513650100 395914 4a8b0ce0 498b0c0f 0f94c3 ff15???????? }
            // n = 6, score = 100
            //   488d0513650100       | mov                 esp, eax
            //   395914               | dec                 eax
            //   4a8b0ce0             | test                eax, eax
            //   498b0c0f             | je                  0xff
            //   0f94c3               | dec                 eax
            //   ff15????????         |                     

        $sequence_19 = { 899ec4000000 c786c800000020964100 c786cc000000a89a4100 c786d0000000289c4100 c786ac00000001000000 33c0 }
            // n = 6, score = 100
            //   899ec4000000         | mov                 dword ptr [esi + 0xc4], ebx
            //   c786c800000020964100     | mov    dword ptr [esi + 0xc8], 0x419620
            //   c786cc000000a89a4100     | mov    dword ptr [esi + 0xcc], 0x419aa8
            //   c786d0000000289c4100     | mov    dword ptr [esi + 0xd0], 0x419c28
            //   c786ac00000001000000     | mov    dword ptr [esi + 0xac], 1
            //   33c0                 | xor                 eax, eax

        $sequence_20 = { c7840dd0feffff242a4200 c745fc06000000 8b95d0feffff 8b4204 8d8de8feffff 51 }
            // n = 6, score = 100
            //   c7840dd0feffff242a4200     | pop    ebp
            //   c745fc06000000       | pop                 ebx
            //   8b95d0feffff         | mov                 eax, edi
            //   8b4204               | pop                 edi
            //   8d8de8feffff         | pop                 esi
            //   51                   | add                 esp, 4

        $sequence_21 = { e8???????? 8d4801 498bc3 482bc1 498bcd 488d544580 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8d4801               | lea                 ebx, [esp + 0x50]
            //   498bc3               | dec                 ecx
            //   482bc1               | mov                 ebx, dword ptr [ebx + 0x20]
            //   498bcd               | dec                 ecx
            //   488d544580           | mov                 ebp, dword ptr [ebx + 0x28]

        $sequence_22 = { 8d4de4 51 56 ff15???????? 85c0 7503 }
            // n = 6, score = 100
            //   8d4de4               | pop                 edi
            //   51                   | pop                 esi
            //   56                   | push                edx
            //   ff15????????         |                     
            //   85c0                 | push                0
            //   7503                 | push                0

        $sequence_23 = { eb02 32c0 4c8d5c2450 498b5b20 498b6b28 }
            // n = 5, score = 100
            //   eb02                 | lea                 eax, [0x16513]
            //   32c0                 | cmp                 dword ptr [ecx + 0x14], ebx
            //   4c8d5c2450           | dec                 edx
            //   498b5b20             | mov                 ecx, dword ptr [eax]
            //   498b6b28             | dec                 ecx

        $sequence_24 = { 83e01f c1f905 8b0c8d40174200 c1e006 8d440104 }
            // n = 5, score = 100
            //   83e01f               | and                 eax, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   8b0c8d40174200       | mov                 ecx, dword ptr [ecx*4 + 0x421740]
            //   c1e006               | shl                 eax, 6
            //   8d440104             | lea                 eax, [ecx + eax + 4]

        $sequence_25 = { c0e804 02c8 8a45fe 80e20f 884df9 }
            // n = 5, score = 100
            //   c0e804               | shr                 al, 4
            //   02c8                 | add                 cl, al
            //   8a45fe               | mov                 al, byte ptr [ebp - 2]
            //   80e20f               | and                 dl, 0xf
            //   884df9               | mov                 byte ptr [ebp - 7], cl

    condition:
        7 of them and filesize < 1112064
}