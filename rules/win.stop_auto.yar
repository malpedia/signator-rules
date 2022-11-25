rule win_stop_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.stop."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stop"
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
        $sequence_0 = { 6a00 ff15???????? 33c9 894604 85c0 }
            // n = 5, score = 500
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   33c9                 | xor                 ecx, ecx
            //   894604               | mov                 dword ptr [esi + 4], eax
            //   85c0                 | test                eax, eax

        $sequence_1 = { ff15???????? 8bf8 85ff 790f }
            // n = 4, score = 500
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi
            //   790f                 | jns                 0x11

        $sequence_2 = { 50 6a00 6a00 6a48 6a00 }
            // n = 5, score = 500
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a48                 | push                0x48
            //   6a00                 | push                0

        $sequence_3 = { 6a00 6a00 ff15???????? 33c9 894604 85c0 }
            // n = 6, score = 500
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   33c9                 | xor                 ecx, ecx
            //   894604               | mov                 dword ptr [esi + 4], eax
            //   85c0                 | test                eax, eax

        $sequence_4 = { c7463c07000000 c7463800000000 66894628 837e2408 720b }
            // n = 5, score = 500
            //   c7463c07000000       | mov                 dword ptr [esi + 0x3c], 7
            //   c7463800000000       | mov                 dword ptr [esi + 0x38], 0
            //   66894628             | mov                 word ptr [esi + 0x28], ax
            //   837e2408             | cmp                 dword ptr [esi + 0x24], 8
            //   720b                 | jb                  0xd

        $sequence_5 = { 03f0 8d047550000000 50 6a40 ff15???????? }
            // n = 5, score = 500
            //   03f0                 | add                 esi, eax
            //   8d047550000000       | lea                 eax, [esi*2 + 0x50]
            //   50                   | push                eax
            //   6a40                 | push                0x40
            //   ff15????????         |                     

        $sequence_6 = { 83c404 33c0 c7463c07000000 c7463800000000 }
            // n = 4, score = 500
            //   83c404               | add                 esp, 4
            //   33c0                 | xor                 eax, eax
            //   c7463c07000000       | mov                 dword ptr [esi + 0x3c], 7
            //   c7463800000000       | mov                 dword ptr [esi + 0x38], 0

        $sequence_7 = { 75e8 6a0a ff7304 ff15???????? 3d02010000 74c4 }
            // n = 6, score = 500
            //   75e8                 | jne                 0xffffffea
            //   6a0a                 | push                0xa
            //   ff7304               | push                dword ptr [ebx + 4]
            //   ff15????????         |                     
            //   3d02010000           | cmp                 eax, 0x102
            //   74c4                 | je                  0xffffffc6

        $sequence_8 = { 8d45e0 50 ffd7 6a01 6a00 6a00 6a00 }
            // n = 7, score = 500
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_9 = { ff7304 ff15???????? 3d02010000 74c4 }
            // n = 4, score = 500
            //   ff7304               | push                dword ptr [ebx + 4]
            //   ff15????????         |                     
            //   3d02010000           | cmp                 eax, 0x102
            //   74c4                 | je                  0xffffffc6

    condition:
        7 of them and filesize < 6029312
}