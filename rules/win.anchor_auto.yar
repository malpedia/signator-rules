rule win_anchor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.anchor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.anchor"
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
        $sequence_0 = { c6400365 eb0a 66c74001646c c640036c }
            // n = 4, score = 800
            //   c6400365             | dec                 eax
            //   eb0a                 | mov                 eax, dword ptr [ebp + 0x100]
            //   66c74001646c         | dec                 eax
            //   c640036c             | mov                 ecx, dword ptr [ebp + 0x108]

        $sequence_1 = { 740c 66c740016578 c6400365 eb0a }
            // n = 4, score = 800
            //   740c                 | dec                 eax
            //   66c740016578         | mov                 ecx, dword ptr [ebp + 0xe0]
            //   c6400365             | dec                 esp
            //   eb0a                 | mov                 ecx, eax

        $sequence_2 = { 8d8dbcfeffff e9???????? 8d8dbcfeffff e9???????? 8b542408 8d420c }
            // n = 6, score = 600
            //   8d8dbcfeffff         | mov                 eax, dword ptr [ebp + 0x100]
            //   e9????????           |                     
            //   8d8dbcfeffff         | dec                 eax
            //   e9????????           |                     
            //   8b542408             | mov                 ecx, dword ptr [ebp + 0x108]
            //   8d420c               | dec                 eax

        $sequence_3 = { b101 e8???????? e8???????? 84c0 }
            // n = 4, score = 600
            //   b101                 | dec                 eax
            //   e8????????           |                     
            //   e8????????           |                     
            //   84c0                 | lea                 ecx, [0x38a52]

        $sequence_4 = { 6a00 6a00 682000000c 6a01 }
            // n = 4, score = 600
            //   6a00                 | lea                 ecx, [0x40b52]
            //   6a00                 | dec                 eax
            //   682000000c           | mov                 eax, dword ptr [ebp + 0x100]
            //   6a01                 | dec                 eax

        $sequence_5 = { c645fc03 50 8d8dbcfeffff e8???????? 68???????? 8d8dbcfeffff e8???????? }
            // n = 7, score = 600
            //   c645fc03             | lea                 ecx, [0x26d51]
            //   50                   | dec                 eax
            //   8d8dbcfeffff         | lea                 ecx, [ebp + 0xe68]
            //   e8????????           |                     
            //   68????????           |                     
            //   8d8dbcfeffff         | dec                 eax
            //   e8????????           |                     

        $sequence_6 = { 66894304 33c0 6a01 894306 }
            // n = 4, score = 600
            //   66894304             | dec                 eax
            //   33c0                 | mov                 eax, dword ptr [ebp + 8]
            //   6a01                 | dec                 eax
            //   894306               | cmp                 dword ptr [eax], 0

        $sequence_7 = { f2e965020000 e9???????? 53 56 57 }
            // n = 5, score = 600
            //   f2e965020000         | mov                 ecx, dword ptr [ebp + 0x108]
            //   e9????????           |                     
            //   53                   | dec                 eax
            //   56                   | lea                 ecx, [0x40b52]
            //   57                   | dec                 eax

        $sequence_8 = { 8bf8 f7e6 0f90c1 f7d9 0bc8 51 e8???????? }
            // n = 7, score = 600
            //   8bf8                 | mov                 dword ptr [ebp + 0xeb8], eax
            //   f7e6                 | dec                 eax
            //   0f90c1               | mov                 eax, dword ptr [ebp + 0xeb8]
            //   f7d9                 | dec                 eax
            //   0bc8                 | mov                 dword ptr [ebp + 0xec0], eax
            //   51                   | dec                 eax
            //   e8????????           |                     

        $sequence_9 = { 7509 33d2 33c9 e8???????? }
            // n = 4, score = 400
            //   7509                 | jne                 0xb
            //   33d2                 | xor                 edx, edx
            //   33c9                 | xor                 ecx, ecx
            //   e8????????           |                     

        $sequence_10 = { 33f6 8bd6 448d7601 418bce 4c3bf3 }
            // n = 5, score = 200
            //   33f6                 | mov                 eax, dword ptr [ebp + 0xf8]
            //   8bd6                 | dec                 eax
            //   448d7601             | mov                 edx, dword ptr [ebp + 0xf0]
            //   418bce               | dec                 eax
            //   4c3bf3               | lea                 ecx, [0x2b952]

        $sequence_11 = { e8???????? 488d0de84f0200 e8???????? 8a1d???????? 84db 7463 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   488d0de84f0200       | dec                 eax
            //   e8????????           |                     
            //   8a1d????????         |                     
            //   84db                 | mov                 dword ptr [ebp + 8], eax
            //   7463                 | dec                 eax

        $sequence_12 = { 488d0d520b0400 e8???????? 488b8500010000 488b8d08010000 }
            // n = 4, score = 200
            //   488d0d520b0400       | lea                 ecx, [0x41b51]
            //   e8????????           |                     
            //   488b8500010000       | nop                 
            //   488b8d08010000       | dec                 eax

        $sequence_13 = { 488d0d528a0300 e8???????? 488b8de0000000 e8???????? }
            // n = 4, score = 200
            //   488d0d528a0300       | pop                 edi
            //   e8????????           |                     
            //   488b8de0000000       | dec                 eax
            //   e8????????           |                     

        $sequence_14 = { 488bf8 bb01000000 48833800 7518 }
            // n = 4, score = 200
            //   488bf8               | mov                 ecx, dword ptr [ebp + 0xe0]
            //   bb01000000           | dec                 esp
            //   48833800             | mov                 ecx, eax
            //   7518                 | dec                 esp

        $sequence_15 = { 488d0d4fb60300 e8???????? e8???????? 48894508 b808000000 }
            // n = 5, score = 200
            //   488d0d4fb60300       | dec                 eax
            //   e8????????           |                     
            //   e8????????           |                     
            //   48894508             | lea                 ecx, [0x3b64f]
            //   b808000000           | dec                 eax

        $sequence_16 = { 488d0d50480300 e8???????? 90 488b8500010000 }
            // n = 4, score = 200
            //   488d0d50480300       | dec                 eax
            //   e8????????           |                     
            //   90                   | lea                 ecx, [0x3b64f]
            //   488b8500010000       | dec                 eax

        $sequence_17 = { f7d9 f7e1 894c2444 8bc2 488d1532b3feff c1e803 }
            // n = 6, score = 200
            //   f7d9                 | mov                 ecx, eax
            //   f7e1                 | dec                 esp
            //   894c2444             | mov                 eax, dword ptr [ebp + 0xf8]
            //   8bc2                 | dec                 eax
            //   488d1532b3feff       | lea                 ecx, [0x38a52]
            //   c1e803               | dec                 eax

        $sequence_18 = { 488d0d52cd0300 e8???????? 90 488b8d00010000 }
            // n = 4, score = 200
            //   488d0d52cd0300       | mov                 dword ptr [ebp + 0xec0], eax
            //   e8????????           |                     
            //   90                   | dec                 eax
            //   488b8d00010000       | lea                 ecx, [0x40b52]

        $sequence_19 = { 488d0d516d0200 e8???????? 488d8d680e0000 e8???????? }
            // n = 4, score = 200
            //   488d0d516d0200       | dec                 eax
            //   e8????????           |                     
            //   488d8d680e0000       | lea                 ecx, [0x28450]
            //   e8????????           |                     

        $sequence_20 = { 488d0d50840200 e8???????? 488d0d48840200 e8???????? }
            // n = 4, score = 200
            //   488d0d50840200       | dec                 eax
            //   e8????????           |                     
            //   488d0d48840200       | mov                 eax, dword ptr [ebp + 0x100]
            //   e8????????           |                     

    condition:
        7 of them and filesize < 778240
}