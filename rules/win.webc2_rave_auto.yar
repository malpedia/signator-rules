rule win_webc2_rave_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.webc2_rave."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_rave"
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
        $sequence_0 = { 51 e8???????? 83c40c 83f8ff 7435 b900010000 33c0 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   83f8ff               | cmp                 eax, -1
            //   7435                 | je                  0x37
            //   b900010000           | mov                 ecx, 0x100
            //   33c0                 | xor                 eax, eax

        $sequence_1 = { 6a00 89442430 c744242c01000000 ff15???????? 83f8ff 0f84b9000000 85c0 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   89442430             | mov                 dword ptr [esp + 0x30], eax
            //   c744242c01000000     | mov                 dword ptr [esp + 0x2c], 1
            //   ff15????????         |                     
            //   83f8ff               | cmp                 eax, -1
            //   0f84b9000000         | je                  0xbf
            //   85c0                 | test                eax, eax

        $sequence_2 = { 8b2d???????? 6a00 8d442414 6a04 50 53 }
            // n = 6, score = 100
            //   8b2d????????         |                     
            //   6a00                 | push                0
            //   8d442414             | lea                 eax, [esp + 0x14]
            //   6a04                 | push                4
            //   50                   | push                eax
            //   53                   | push                ebx

        $sequence_3 = { 895c2444 895c2448 ffd7 3bc3 894610 7517 }
            // n = 6, score = 100
            //   895c2444             | mov                 dword ptr [esp + 0x44], ebx
            //   895c2448             | mov                 dword ptr [esp + 0x48], ebx
            //   ffd7                 | call                edi
            //   3bc3                 | cmp                 eax, ebx
            //   894610               | mov                 dword ptr [esi + 0x10], eax
            //   7517                 | jne                 0x19

        $sequence_4 = { 8a442410 7404 84c0 7418 8b742418 }
            // n = 5, score = 100
            //   8a442410             | mov                 al, byte ptr [esp + 0x10]
            //   7404                 | je                  6
            //   84c0                 | test                al, al
            //   7418                 | je                  0x1a
            //   8b742418             | mov                 esi, dword ptr [esp + 0x18]

        $sequence_5 = { e8???????? 8b4500 8b4c2420 85f6 c6040800 7409 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8b4500               | mov                 eax, dword ptr [ebp]
            //   8b4c2420             | mov                 ecx, dword ptr [esp + 0x20]
            //   85f6                 | test                esi, esi
            //   c6040800             | mov                 byte ptr [eax + ecx], 0
            //   7409                 | je                  0xb

        $sequence_6 = { 49 7423 8dbc24b0040000 83c9ff }
            // n = 4, score = 100
            //   49                   | dec                 ecx
            //   7423                 | je                  0x25
            //   8dbc24b0040000       | lea                 edi, [esp + 0x4b0]
            //   83c9ff               | or                  ecx, 0xffffffff

        $sequence_7 = { 8d04b2 8944241c 7e90 8b442420 b903000000 99 f7f9 }
            // n = 7, score = 100
            //   8d04b2               | lea                 eax, [edx + esi*4]
            //   8944241c             | mov                 dword ptr [esp + 0x1c], eax
            //   7e90                 | jle                 0xffffff92
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   b903000000           | mov                 ecx, 3
            //   99                   | cdq                 
            //   f7f9                 | idiv                ecx

        $sequence_8 = { 50 56 57 51 68???????? }
            // n = 5, score = 100
            //   50                   | push                eax
            //   56                   | push                esi
            //   57                   | push                edi
            //   51                   | push                ecx
            //   68????????           |                     

        $sequence_9 = { 8854040b 884c340c 7cd5 8bac2418020000 33c9 33f6 }
            // n = 6, score = 100
            //   8854040b             | mov                 byte ptr [esp + eax + 0xb], dl
            //   884c340c             | mov                 byte ptr [esp + esi + 0xc], cl
            //   7cd5                 | jl                  0xffffffd7
            //   8bac2418020000       | mov                 ebp, dword ptr [esp + 0x218]
            //   33c9                 | xor                 ecx, ecx
            //   33f6                 | xor                 esi, esi

    condition:
        7 of them and filesize < 57344
}