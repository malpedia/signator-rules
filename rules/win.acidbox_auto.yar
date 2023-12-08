rule win_acidbox_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.acidbox."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.acidbox"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
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
        $sequence_0 = { 418bb590000000 4903f4 4889742438 413b8594000000 0f8311010000 397e0c 0f8408010000 }
            // n = 7, score = 400
            //   418bb590000000       | dec                 eax
            //   4903f4               | mov                 dword ptr [eax + 8], ecx
            //   4889742438           | push                edi
            //   413b8594000000       | dec                 eax
            //   0f8311010000         | sub                 esp, 0x30
            //   397e0c               | dec                 eax
            //   0f8408010000         | mov                 edi, dword ptr [esp + 0x60]

        $sequence_1 = { 4154 4155 4156 4157 4883ec28 4c8b7128 448b6108 }
            // n = 7, score = 400
            //   4154                 | dec                 edi
            //   4155                 | jne                 0x1db3
            //   4156                 | dec                 esp
            //   4157                 | mov                 ebp, dword ptr [esp + 0x40]
            //   4883ec28             | dec                 eax
            //   4c8b7128             | lea                 eax, [esp + 0x40]
            //   448b6108             | dec                 eax

        $sequence_2 = { c780d8feffffd3731048 c780dcfeffffffff00ff c780e0feffffffe0cccc c780e4feffffffff0000 4d8920 4d8921 }
            // n = 6, score = 400
            //   c780d8feffffd3731048     | dec    ecx
            //   c780dcfeffffffff00ff     | mov    ecx, ecx
            //   c780e0feffffffe0cccc     | dec    ecx
            //   c780e4feffffffff0000     | mov    edi, ecx
            //   4d8920               | dec                 eax
            //   4d8921               | xor                 eax, edx

        $sequence_3 = { 0fb6ca 4103c9 4403f0 0fb74562 41d3e0 418bc9 49ffc7 }
            // n = 7, score = 400
            //   0fb6ca               | test                edx, edx
            //   4103c9               | je                  0x1240
            //   4403f0               | and                 dword ptr [edi + 0xb0], 0
            //   0fb74562             | mov                 eax, ecx
            //   41d3e0               | dec                 eax
            //   418bc9               | and                 dword ptr [esp + 0x208], 0
            //   49ffc7               | and                 dword ptr [esp + 0x210], 0

        $sequence_4 = { ff15???????? 8d043e 898318170000 eb2f 8d8702010000 }
            // n = 5, score = 400
            //   ff15????????         |                     
            //   8d043e               | inc                 ecx
            //   898318170000         | and                 byte ptr [esi + 0x3c], 0xf7
            //   eb2f                 | dec                 eax
            //   8d8702010000         | mov                 ecx, dword ptr [edi + 0x1b8]

        $sequence_5 = { 4883c438 c3 488bc4 48895810 48897018 57 4154 }
            // n = 7, score = 400
            //   4883c438             | dec                 eax
            //   c3                   | lea                 eax, [ebp - 0x80]
            //   488bc4               | dec                 eax
            //   48895810             | lea                 edx, [ebp - 0x68]
            //   48897018             | dec                 eax
            //   57                   | lea                 ecx, [ebp - 0x28]
            //   4154                 | dec                 esp

        $sequence_6 = { eb09 4584c0 7908 418b4124 89442420 85c0 }
            // n = 6, score = 400
            //   eb09                 | inc                 esp
            //   4584c0               | mov                 eax, dword ptr [edi + 0x20]
            //   7908                 | dec                 eax
            //   418b4124             | mov                 edx, dword ptr [edi + 0x18]
            //   89442420             | mov                 ecx, dword ptr [edi + 0xc]
            //   85c0                 | jmp                 0x1e31

        $sequence_7 = { 4c8b4de0 c70705000000 f7471000040000 0f840c010000 8b5f48 413bdd 410f47dd }
            // n = 7, score = 400
            //   4c8b4de0             | dec                 eax
            //   c70705000000         | mov                 ecx, dword ptr [ebx + 8]
            //   f7471000040000       | xor                 edi, edi
            //   0f840c010000         | dec                 eax
            //   8b5f48               | test                ecx, ecx
            //   413bdd               | je                  0x182c
            //   410f47dd             | jne                 0x184d

        $sequence_8 = { 7d07 8bd7 413bc7 7d03 418bd1 8b4b28 488b4310 }
            // n = 7, score = 400
            //   7d07                 | dec                 eax
            //   8bd7                 | sub                 edx, eax
            //   413bc7               | inc                 ecx
            //   7d03                 | mov                 eax, dword ptr [esi + 0x2c]
            //   418bd1               | mov                 esi, 1
            //   8b4b28               | mov                 eax, edx
            //   488b4310             | inc                 edx

        $sequence_9 = { 0fb79f02040000 418b8a14170000 418bc3 2bc3 }
            // n = 4, score = 400
            //   0fb79f02040000       | dec                 eax
            //   418b8a14170000       | lea                 ecx, [ebp + 0x17]
            //   418bc3               | jne                 0xffffec10
            //   2bc3                 | mov                 dword ptr [edi], 0x14

    condition:
        7 of them and filesize < 589824
}