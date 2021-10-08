rule win_abaddon_pos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.abaddon_pos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.abaddon_pos"
        malpedia_rule_date = "20211007"
        malpedia_hash = "e5b790e0f888f252d49063a1251ca60ec2832535"
        malpedia_version = "20211008"
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
        $sequence_0 = { 48 8b8ec0050000 48 c7c220bf0200 ff15???????? 48 83c420 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   8b8ec0050000         | mov                 ecx, dword ptr [esi + 0x5c0]
            //   48                   | dec                 eax
            //   c7c220bf0200         | mov                 edx, 0x2bf20
            //   ff15????????         |                     
            //   48                   | dec                 eax
            //   83c420               | add                 esp, 0x20

        $sequence_1 = { 48 8b8ec8050000 48 c7c200d00700 }
            // n = 4, score = 100
            //   48                   | dec                 eax
            //   8b8ec8050000         | mov                 ecx, dword ptr [esi + 0x5c8]
            //   48                   | dec                 eax
            //   c7c200d00700         | mov                 edx, 0x7d000

        $sequence_2 = { 8918 48 83c008 48 }
            // n = 4, score = 100
            //   8918                 | mov                 dword ptr [eax], ebx
            //   48                   | dec                 eax
            //   83c008               | add                 eax, 8
            //   48                   | dec                 eax

        $sequence_3 = { 6a00 ff15???????? 83f800 7502 ebe4 50 }
            // n = 6, score = 100
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   83f800               | cmp                 eax, 0
            //   7502                 | jne                 4
            //   ebe4                 | jmp                 0xffffffe6
            //   50                   | push                eax

        $sequence_4 = { 8d96c0010000 52 53 ff15???????? e8???????? }
            // n = 5, score = 100
            //   8d96c0010000         | lea                 edx, dword ptr [esi + 0x1c0]
            //   52                   | push                edx
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   e8????????           |                     

        $sequence_5 = { c70300000000 48 8b9ed0050000 48 81c300040000 48 }
            // n = 6, score = 100
            //   c70300000000         | mov                 dword ptr [ebx], 0
            //   48                   | dec                 eax
            //   8b9ed0050000         | mov                 ebx, dword ptr [esi + 0x5d0]
            //   48                   | dec                 eax
            //   81c300040000         | add                 ebx, 0x400
            //   48                   | dec                 eax

        $sequence_6 = { 83c420 48 8986b0050000 48 83ec20 }
            // n = 5, score = 100
            //   83c420               | add                 esp, 0x20
            //   48                   | dec                 eax
            //   8986b0050000         | mov                 dword ptr [esi + 0x5b0], eax
            //   48                   | dec                 eax
            //   83ec20               | sub                 esp, 0x20

        $sequence_7 = { 83ec20 48 8d4e2c ff15???????? 48 83c420 }
            // n = 6, score = 100
            //   83ec20               | sub                 esp, 0x20
            //   48                   | dec                 eax
            //   8d4e2c               | lea                 ecx, dword ptr [esi + 0x2c]
            //   ff15????????         |                     
            //   48                   | dec                 eax
            //   83c420               | add                 esp, 0x20

        $sequence_8 = { 0500040000 833800 0f860d020000 48 }
            // n = 4, score = 100
            //   0500040000           | add                 eax, 0x400
            //   833800               | cmp                 dword ptr [eax], 0
            //   0f860d020000         | jbe                 0x213
            //   48                   | dec                 eax

        $sequence_9 = { 83c420 48 83ec20 48 8b8ed0050000 48 }
            // n = 6, score = 100
            //   83c420               | add                 esp, 0x20
            //   48                   | dec                 eax
            //   83ec20               | sub                 esp, 0x20
            //   48                   | dec                 eax
            //   8b8ed0050000         | mov                 ecx, dword ptr [esi + 0x5d0]
            //   48                   | dec                 eax

        $sequence_10 = { 83f809 7603 83e809 ba00000000 eb05 ba01000000 0186ac010000 }
            // n = 7, score = 100
            //   83f809               | cmp                 eax, 9
            //   7603                 | jbe                 5
            //   83e809               | sub                 eax, 9
            //   ba00000000           | mov                 edx, 0
            //   eb05                 | jmp                 7
            //   ba01000000           | mov                 edx, 1
            //   0186ac010000         | add                 dword ptr [esi + 0x1ac], eax

        $sequence_11 = { 68???????? 6a00 6a00 ff15???????? 83f800 7505 e9???????? }
            // n = 7, score = 100
            //   68????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   83f800               | cmp                 eax, 0
            //   7505                 | jne                 7
            //   e9????????           |                     

        $sequence_12 = { 50 ff15???????? 83f800 7502 eba6 43 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83f800               | cmp                 eax, 0
            //   7502                 | jne                 4
            //   eba6                 | jmp                 0xffffffa8
            //   43                   | inc                 ebx

        $sequence_13 = { 8b8684010000 39867c010000 7205 e9???????? eb91 81be0c01000080cf0700 7607 }
            // n = 7, score = 100
            //   8b8684010000         | mov                 eax, dword ptr [esi + 0x184]
            //   39867c010000         | cmp                 dword ptr [esi + 0x17c], eax
            //   7205                 | jb                  7
            //   e9????????           |                     
            //   eb91                 | jmp                 0xffffff93
            //   81be0c01000080cf0700     | cmp    dword ptr [esi + 0x10c], 0x7cf80
            //   7607                 | jbe                 9

        $sequence_14 = { 8b740e83 f8 007509 310b 29c3 31c0 }
            // n = 6, score = 100
            //   8b740e83             | mov                 esi, dword ptr [esi + ecx - 0x7d]
            //   f8                   | clc                 
            //   007509               | add                 byte ptr [ebp + 9], dh
            //   310b                 | xor                 dword ptr [ebx], ecx
            //   29c3                 | sub                 ebx, eax
            //   31c0                 | xor                 eax, eax

        $sequence_15 = { 50 ff15???????? b804140000 0faf45f4 038560feffff 6a00 6a00 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   b804140000           | mov                 eax, 0x1404
            //   0faf45f4             | imul                eax, dword ptr [ebp - 0xc]
            //   038560feffff         | add                 eax, dword ptr [ebp - 0x1a0]
            //   6a00                 | push                0
            //   6a00                 | push                0

    condition:
        7 of them and filesize < 40960
}