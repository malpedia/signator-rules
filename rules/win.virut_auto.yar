rule win_virut_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.virut."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.virut"
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
        $sequence_0 = { 03c3 8b5078 03d3 8b7220 8b4a18 8d3433 51 }
            // n = 7, score = 200
            //   03c3                 | add                 eax, ebx
            //   8b5078               | mov                 edx, dword ptr [eax + 0x78]
            //   03d3                 | add                 edx, ebx
            //   8b7220               | mov                 esi, dword ptr [edx + 0x20]
            //   8b4a18               | mov                 ecx, dword ptr [edx + 0x18]
            //   8d3433               | lea                 esi, [ebx + esi]
            //   51                   | push                ecx

        $sequence_1 = { 75f9 2bc1 8bf8 33f6 85ff 7e2c e8???????? }
            // n = 7, score = 200
            //   75f9                 | jne                 0xfffffffb
            //   2bc1                 | sub                 eax, ecx
            //   8bf8                 | mov                 edi, eax
            //   33f6                 | xor                 esi, esi
            //   85ff                 | test                edi, edi
            //   7e2c                 | jle                 0x2e
            //   e8????????           |                     

        $sequence_2 = { 8d8424d0000000 68???????? 50 ff15???????? 83c410 53 }
            // n = 6, score = 200
            //   8d8424d0000000       | lea                 eax, [esp + 0xd0]
            //   68????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c410               | add                 esp, 0x10
            //   53                   | push                ebx

        $sequence_3 = { 0f85ef000000 885c2420 885c2421 885c2422 885c2423 }
            // n = 5, score = 200
            //   0f85ef000000         | jne                 0xf5
            //   885c2420             | mov                 byte ptr [esp + 0x20], bl
            //   885c2421             | mov                 byte ptr [esp + 0x21], bl
            //   885c2422             | mov                 byte ptr [esp + 0x22], bl
            //   885c2423             | mov                 byte ptr [esp + 0x23], bl

        $sequence_4 = { 8b44241c 6bc00a 0fbec9 47 }
            // n = 4, score = 200
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   6bc00a               | imul                eax, eax, 0xa
            //   0fbec9               | movsx               ecx, cl
            //   47                   | inc                 edi

        $sequence_5 = { 6a00 6800000008 6a40 51 52 6a0e 50 }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   6800000008           | push                0x8000000
            //   6a40                 | push                0x40
            //   51                   | push                ecx
            //   52                   | push                edx
            //   6a0e                 | push                0xe
            //   50                   | push                eax

        $sequence_6 = { b928010000 97 2be1 890c24 }
            // n = 4, score = 200
            //   b928010000           | mov                 ecx, 0x128
            //   97                   | xchg                eax, edi
            //   2be1                 | sub                 esp, ecx
            //   890c24               | mov                 dword ptr [esp], ecx

        $sequence_7 = { aa 3c5c 74ec 3c2e }
            // n = 4, score = 200
            //   aa                   | stosb               byte ptr es:[edi], al
            //   3c5c                 | cmp                 al, 0x5c
            //   74ec                 | je                  0xffffffee
            //   3c2e                 | cmp                 al, 0x2e

        $sequence_8 = { f7f7 80c261 889434d0010000 46 }
            // n = 4, score = 200
            //   f7f7                 | div                 edi
            //   80c261               | add                 dl, 0x61
            //   889434d0010000       | mov                 byte ptr [esp + esi + 0x1d0], dl
            //   46                   | inc                 esi

        $sequence_9 = { 6a05 8bcc 50 8bd4 50 54 }
            // n = 6, score = 200
            //   6a05                 | push                5
            //   8bcc                 | mov                 ecx, esp
            //   50                   | push                eax
            //   8bd4                 | mov                 edx, esp
            //   50                   | push                eax
            //   54                   | push                esp

        $sequence_10 = { 33c0 6a10 59 f3ab 50 50 50 }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   6a10                 | push                0x10
            //   59                   | pop                 ecx
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   50                   | push                eax
            //   50                   | push                eax
            //   50                   | push                eax

        $sequence_11 = { a3???????? 8d8424e0030000 50 6a02 ff15???????? 895c2414 }
            // n = 6, score = 200
            //   a3????????           |                     
            //   8d8424e0030000       | lea                 eax, [esp + 0x3e0]
            //   50                   | push                eax
            //   6a02                 | push                2
            //   ff15????????         |                     
            //   895c2414             | mov                 dword ptr [esp + 0x14], ebx

        $sequence_12 = { 8d442410 50 6800040000 8d842404060000 50 ff742428 }
            // n = 6, score = 200
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   50                   | push                eax
            //   6800040000           | push                0x400
            //   8d842404060000       | lea                 eax, [esp + 0x604]
            //   50                   | push                eax
            //   ff742428             | push                dword ptr [esp + 0x28]

        $sequence_13 = { 59 f7f1 33f6 8bca 83c107 3bcb }
            // n = 6, score = 200
            //   59                   | pop                 ecx
            //   f7f1                 | div                 ecx
            //   33f6                 | xor                 esi, esi
            //   8bca                 | mov                 ecx, edx
            //   83c107               | add                 ecx, 7
            //   3bcb                 | cmp                 ecx, ebx

        $sequence_14 = { 33d2 8bcf 52 f6d9 }
            // n = 4, score = 200
            //   33d2                 | xor                 edx, edx
            //   8bcf                 | mov                 ecx, edi
            //   52                   | push                edx
            //   f6d9                 | neg                 cl

        $sequence_15 = { 57 6a44 58 8d9704010000 ab }
            // n = 5, score = 200
            //   57                   | push                edi
            //   6a44                 | push                0x44
            //   58                   | pop                 eax
            //   8d9704010000         | lea                 edx, [edi + 0x104]
            //   ab                   | stosd               dword ptr es:[edi], eax

    condition:
        7 of them and filesize < 98304
}