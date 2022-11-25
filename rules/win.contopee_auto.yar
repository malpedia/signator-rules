rule win_contopee_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.contopee."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.contopee"
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
        $sequence_0 = { 83c40c 83c004 50 6a40 ff15???????? 8b8e64040000 8b942430010000 }
            // n = 7, score = 100
            //   83c40c               | add                 esp, 0xc
            //   83c004               | add                 eax, 4
            //   50                   | push                eax
            //   6a40                 | push                0x40
            //   ff15????????         |                     
            //   8b8e64040000         | mov                 ecx, dword ptr [esi + 0x464]
            //   8b942430010000       | mov                 edx, dword ptr [esp + 0x130]

        $sequence_1 = { 56 6a08 53 e8???????? 83c40c 53 ff15???????? }
            // n = 7, score = 100
            //   56                   | push                esi
            //   6a08                 | push                8
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   53                   | push                ebx
            //   ff15????????         |                     

        $sequence_2 = { 83c40c 83c004 50 6a40 }
            // n = 4, score = 100
            //   83c40c               | add                 esp, 0xc
            //   83c004               | add                 eax, 4
            //   50                   | push                eax
            //   6a40                 | push                0x40

        $sequence_3 = { 8907 ff15???????? 8903 8b17 56 }
            // n = 5, score = 100
            //   8907                 | mov                 dword ptr [edi], eax
            //   ff15????????         |                     
            //   8903                 | mov                 dword ptr [ebx], eax
            //   8b17                 | mov                 edx, dword ptr [edi]
            //   56                   | push                esi

        $sequence_4 = { 7418 668b1455a42a0110 52 ff15???????? 8b4c2418 668901 }
            // n = 6, score = 100
            //   7418                 | je                  0x1a
            //   668b1455a42a0110     | mov                 dx, word ptr [edx*2 + 0x10012aa4]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]
            //   668901               | mov                 word ptr [ecx], ax

        $sequence_5 = { 0bc3 e9???????? 8d842410010000 6a00 50 8d8c241c020000 e8???????? }
            // n = 7, score = 100
            //   0bc3                 | or                  eax, ebx
            //   e9????????           |                     
            //   8d842410010000       | lea                 eax, [esp + 0x110]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   8d8c241c020000       | lea                 ecx, [esp + 0x21c]
            //   e8????????           |                     

        $sequence_6 = { ff15???????? 8d8e28020000 50 51 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   8d8e28020000         | lea                 ecx, [esi + 0x228]
            //   50                   | push                eax
            //   51                   | push                ecx

        $sequence_7 = { 83c408 85f6 7439 8d542408 6a00 52 66c7060000 }
            // n = 7, score = 100
            //   83c408               | add                 esp, 8
            //   85f6                 | test                esi, esi
            //   7439                 | je                  0x3b
            //   8d542408             | lea                 edx, [esp + 8]
            //   6a00                 | push                0
            //   52                   | push                edx
            //   66c7060000           | mov                 word ptr [esi], 0

        $sequence_8 = { 755c 8b442414 8b4c2410 3bc7 7c10 7f04 3bcb }
            // n = 7, score = 100
            //   755c                 | jne                 0x5e
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   3bc7                 | cmp                 eax, edi
            //   7c10                 | jl                  0x12
            //   7f04                 | jg                  6
            //   3bcb                 | cmp                 ecx, ebx

        $sequence_9 = { 4f 81ff00010000 730a 33db 8a9f94120110 eb0d }
            // n = 6, score = 100
            //   4f                   | dec                 edi
            //   81ff00010000         | cmp                 edi, 0x100
            //   730a                 | jae                 0xc
            //   33db                 | xor                 ebx, ebx
            //   8a9f94120110         | mov                 bl, byte ptr [edi + 0x10011294]
            //   eb0d                 | jmp                 0xf

    condition:
        7 of them and filesize < 180224
}