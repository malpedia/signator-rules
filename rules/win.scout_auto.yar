rule win_scout_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.scout."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.scout"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
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
        $sequence_0 = { 57 4883ec20 488bd9 488d3d5cd1feff 488bcf e8???????? 85c0 }
            // n = 7, score = 100
            //   57                   | inc                 esp
            //   4883ec20             | lea                 eax, [ebx + 3]
            //   488bd9               | mov                 dword ptr [esp + 0x28], ebx
            //   488d3d5cd1feff       | dec                 eax
            //   488bcf               | lea                 ecx, [0xa033]
            //   e8????????           |                     
            //   85c0                 | inc                 ebp

        $sequence_1 = { ff15???????? 488d0d80960100 eb0c 83f901 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   488d0d80960100       | lea                 eax, [0x87fd]
            //   eb0c                 | dec                 esp
            //   83f901               | lea                 eax, [0x87e9]

        $sequence_2 = { 488d050ef70000 4a8b04e8 42385cf838 0f8df5000000 e8???????? }
            // n = 5, score = 100
            //   488d050ef70000       | dec                 eax
            //   4a8b04e8             | test                eax, eax
            //   42385cf838           | xor                 ecx, ecx
            //   0f8df5000000         | dec                 eax
            //   e8????????           |                     

        $sequence_3 = { 488bd9 4c8d0d38c00000 b91c000000 4c8d0528c00000 488d1525c00000 e8???????? 4885c0 }
            // n = 7, score = 100
            //   488bd9               | lea                 ebx, [0x190ea]
            //   4c8d0d38c00000       | inc                 ecx
            //   b91c000000           | mov                 eax, 0x104
            //   4c8d0528c00000       | dec                 eax
            //   488d1525c00000       | mov                 edx, ebx
            //   e8????????           |                     
            //   4885c0               | xor                 ecx, ecx

        $sequence_4 = { 85c0 7410 488d0d98ca0100 4883c428 e9???????? e8???????? }
            // n = 6, score = 100
            //   85c0                 | mov                 ecx, 0x16
            //   7410                 | dec                 eax
            //   488d0d98ca0100       | sub                 esp, 0x28
            //   4883c428             | inc                 ebp
            //   e9????????           |                     
            //   e8????????           |                     

        $sequence_5 = { c745d41398db1a c745d862452312 c745dca8837182 0f1045d0 c744242801000000 }
            // n = 5, score = 100
            //   c745d41398db1a       | dec                 eax
            //   c745d862452312       | lea                 eax, [0x1bd7a]
            //   c745dca8837182       | dec                 eax
            //   0f1045d0             | cmp                 ebx, eax
            //   c744242801000000     | je                  0xd22

        $sequence_6 = { 418ac7 84c0 0f8408010000 8b4c2448 488d15d214ffff 2b4c244c }
            // n = 6, score = 100
            //   418ac7               | dec                 ebp
            //   84c0                 | mov                 ebp, esp
            //   0f8408010000         | dec                 ecx
            //   8b4c2448             | sar                 ebp, 6
            //   488d15d214ffff       | dec                 ecx
            //   2b4c244c             | mov                 eax, esi

        $sequence_7 = { b84d5a0000 663905c5ccffff 7578 48630df8ccffff 488d15b5ccffff 4803ca 813950450000 }
            // n = 7, score = 100
            //   b84d5a0000           | dec                 eax
            //   663905c5ccffff       | lea                 ebx, [ebx + 2]
            //   7578                 | dec                 eax
            //   48630df8ccffff       | mov                 eax, 0xffffffff
            //   488d15b5ccffff       | dec                 eax
            //   4803ca               | lea                 ecx, [ebp - 0x10]
            //   813950450000         | inc                 edi

        $sequence_8 = { 4883f80e 7773 8b8486bc010100 4803c6 ffe0 }
            // n = 5, score = 100
            //   4883f80e             | mov                 edx, ebx
            //   7773                 | dec                 esp
            //   8b8486bc010100       | lea                 eax, [0xfffef9ef]
            //   4803c6               | dec                 eax
            //   ffe0                 | cmp                 dword ptr [esp + 0x30], ebx

        $sequence_9 = { e8???????? 48391d???????? 7505 83c8ff eb75 488beb 488d35634f0100 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   48391d????????       |                     
            //   7505                 | or                  esi, 0xffffffff
            //   83c8ff               | dec                 ecx
            //   eb75                 | cmp                 eax, esi
            //   488beb               | je                  0x108
            //   488d35634f0100       | dec                 eax

    condition:
        7 of them and filesize < 315392
}