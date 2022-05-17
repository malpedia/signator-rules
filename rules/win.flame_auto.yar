rule win_flame_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.flame."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.flame"
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
        $sequence_0 = { 85c9 741a 83f901 7415 e8???????? }
            // n = 5, score = 400
            //   85c9                 | test                ecx, ecx
            //   741a                 | je                  0x1c
            //   83f901               | cmp                 ecx, 1
            //   7415                 | je                  0x17
            //   e8????????           |                     

        $sequence_1 = { ffd7 90 eb00 4883c430 5f 5e }
            // n = 6, score = 200
            //   ffd7                 | add                 esp, 0x20
            //   90                   | je                  0x17
            //   eb00                 | dec                 eax
            //   4883c430             | mov                 ebx, dword ptr [ebx + 0x1c]
            //   5f                   | dec                 eax
            //   5e                   | test                ebx, ebx

        $sequence_2 = { ff15???????? 50 68???????? ff7508 ff15???????? 83c40c eb0f }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   50                   | or                  eax, 0xffffffff
            //   68????????           |                     
            //   ff7508               | test                ecx, ecx
            //   ff15????????         |                     
            //   83c40c               | je                  0x1e
            //   eb0f                 | cmp                 ecx, 1

        $sequence_3 = { ff7608 e8???????? 59 59 85c0 0f8495000000 8b4e0c }
            // n = 7, score = 200
            //   ff7608               | je                  0x17
            //   e8????????           |                     
            //   59                   | mov                 dword ptr [eax], 0x16
            //   59                   | or                  eax, 0xffffffff
            //   85c0                 | test                ecx, ecx
            //   0f8495000000         | je                  0x1c
            //   8b4e0c               | cmp                 ecx, 1

        $sequence_4 = { 7415 488b55e8 8b4f18 448bc3 }
            // n = 4, score = 200
            //   7415                 | dec                 eax
            //   488b55e8             | mov                 ecx, dword ptr [ebp - 0x48]
            //   8b4f18               | dec                 eax
            //   448bc3               | test                ecx, ecx

        $sequence_5 = { 7415 0fb702 0fb74c45d8 66893c4e }
            // n = 4, score = 200
            //   7415                 | dec                 eax
            //   0fb702               | test                ebx, ebx
            //   0fb74c45d8           | jne                 0xfffffffa
            //   66893c4e             | dec                 eax

        $sequence_6 = { 57 8b7d10 398684000000 7e54 }
            // n = 4, score = 200
            //   57                   | je                  0x1c
            //   8b7d10               | cmp                 ecx, 1
            //   398684000000         | je                  0x17
            //   7e54                 | mov                 dword ptr [eax], 0x16

        $sequence_7 = { 85c0 7529 8b0e 8b4604 2bc1 50 8d45f0 }
            // n = 7, score = 200
            //   85c0                 | mov                 dword ptr [eax], 0x16
            //   7529                 | cmp                 ecx, 1
            //   8b0e                 | je                  0x17
            //   8b4604               | mov                 dword ptr [eax], 0x16
            //   2bc1                 | je                  0x1c
            //   50                   | cmp                 ecx, 1
            //   8d45f0               | je                  0x17

        $sequence_8 = { 7415 488b4db8 4885c9 7405 e8???????? }
            // n = 5, score = 200
            //   7415                 | je                  0x17
            //   488b4db8             | dec                 eax
            //   4885c9               | mov                 ecx, dword ptr [ebp - 0x48]
            //   7405                 | dec                 eax
            //   e8????????           |                     

        $sequence_9 = { 7415 488b5b1c 4885db 75f1 }
            // n = 4, score = 200
            //   7415                 | dec                 eax
            //   488b5b1c             | mov                 edx, dword ptr [ebp - 0x18]
            //   4885db               | mov                 ecx, dword ptr [edi + 0x18]
            //   75f1                 | inc                 esp

        $sequence_10 = { 50 ff7510 ff750c 68???????? 6a67 ff35???????? }
            // n = 6, score = 200
            //   50                   | je                  0x1a
            //   ff7510               | test                ecx, ecx
            //   ff750c               | je                  0x1e
            //   68????????           |                     
            //   6a67                 | cmp                 ecx, 1
            //   ff35????????         |                     

        $sequence_11 = { 7414 6641890424 48ffc6 4983c402 48ffcf 4885ff 7f84 }
            // n = 7, score = 200
            //   7414                 | jne                 0xfffffffa
            //   6641890424           | dec                 eax
            //   48ffc6               | add                 esp, 0x20
            //   4983c402             | pop                 ebx
            //   48ffcf               | je                  0x17
            //   4885ff               | dec                 eax
            //   7f84                 | mov                 ebx, dword ptr [ebx + 0x1c]

        $sequence_12 = { 59 59 a3???????? 85c0 0f8415ffffff 68???????? ff35???????? }
            // n = 7, score = 200
            //   59                   | cmp                 ecx, 1
            //   59                   | je                  0x1a
            //   a3????????           |                     
            //   85c0                 | mov                 dword ptr [eax], 0x16
            //   0f8415ffffff         | cmp                 ecx, 1
            //   68????????           |                     
            //   ff35????????         |                     

        $sequence_13 = { 7415 e8???????? c70016000000 e8???????? 83c8ff eb0c }
            // n = 6, score = 200
            //   7415                 | jne                 0xfffffffa
            //   e8????????           |                     
            //   c70016000000         | je                  0x17
            //   e8????????           |                     
            //   83c8ff               | dec                 eax
            //   eb0c                 | mov                 ebx, dword ptr [ebx + 0x1c]

        $sequence_14 = { 7303 8d4dbc 837db410 8b45a0 7303 }
            // n = 5, score = 200
            //   7303                 | je                  0x1a
            //   8d4dbc               | je                  0x1c
            //   837db410             | cmp                 ecx, 1
            //   8b45a0               | je                  0x17
            //   7303                 | mov                 dword ptr [eax], 0x16

    condition:
        7 of them and filesize < 1676288
}