rule win_havoc_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.havoc."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.havoc"
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
        $sequence_0 = { 488d542430 4c8d4c2428 6689442432 488b05???????? }
            // n = 4, score = 800
            //   488d542430           | add                 esp, 0x20
            //   4c8d4c2428           | dec                 eax
            //   6689442432           | mov                 eax, dword ptr [eax]
            //   488b05????????       |                     

        $sequence_1 = { 4885c0 7504 31f6 eb08 488b4030 ffc3 }
            // n = 6, score = 800
            //   4885c0               | inc                 esi
            //   7504                 | dec                 eax
            //   31f6                 | lea                 edx, [esp + 0x30]
            //   eb08                 | dec                 esp
            //   488b4030             | lea                 ecx, [esp + 0x28]
            //   ffc3                 | mov                 word ptr [esp + 0x32], ax

        $sequence_2 = { 48894304 4803430c 4889c1 e8???????? }
            // n = 4, score = 800
            //   48894304             | mov                 eax, dword ptr [esp + 0x60]
            //   4803430c             | dec                 eax
            //   4889c1               | mov                 edx, esi
            //   e8????????           |                     

        $sequence_3 = { e9???????? 83f806 755f 8b4c244c 85c9 7512 31c0 }
            // n = 7, score = 800
            //   e9????????           |                     
            //   83f806               | mov                 ecx, dword ptr [ecx + eax + 0x88]
            //   755f                 | dec                 esp
            //   8b4c244c             | mov                 edx, esp
            //   85c9                 | mov                 ebx, eax
            //   7512                 | dec                 esp
            //   31c0                 | add                 ebx, esp

        $sequence_4 = { 41b914000008 f3ab 488b05???????? b901000000 488b00 }
            // n = 5, score = 800
            //   41b914000008         | dec                 eax
            //   f3ab                 | lea                 ecx, [esp + 0x46]
            //   488b05????????       |                     
            //   b901000000           | jne                 0x94f
            //   488b00               | dec                 eax

        $sequence_5 = { eb1c 83f80a 751a 837c244c00 }
            // n = 4, score = 800
            //   eb1c                 | dec                 esp
            //   83f80a               | mov                 ecx, esp
            //   751a                 | dec                 eax
            //   837c244c00           | mov                 dword ptr [esp + 0x30], eax

        $sequence_6 = { f3a5 488bbc2480000000 488b742460 b934010000 f3a5 }
            // n = 5, score = 800
            //   f3a5                 | mov                 eax, 0x20
            //   488bbc2480000000     | xor                 edx, edx
            //   488b742460           | dec                 eax
            //   b934010000           | mov                 eax, dword ptr [ebx]
            //   f3a5                 | call                dword ptr [eax + 0x464]

        $sequence_7 = { 4429c0 c3 ffc1 4883c228 }
            // n = 4, score = 800
            //   4429c0               | inc                 ecx
            //   c3                   | push                esi
            //   ffc1                 | xor                 eax, eax
            //   4883c228             | inc                 ebp

        $sequence_8 = { c744247030000000 488d4b10 4889442440 8b44245c }
            // n = 4, score = 800
            //   c744247030000000     | dec                 eax
            //   488d4b10             | mov                 dword ptr [esp + 0x30], 0
            //   4889442440           | dec                 eax
            //   8b44245c             | mov                 dword ptr [esp + 0x38], 0

        $sequence_9 = { 4154 41bcffffffff 55 31ed 57 56 31f6 }
            // n = 7, score = 800
            //   4154                 | mov                 eax, dword ptr [eax + 0x18]
            //   41bcffffffff         | dec                 eax
            //   55                   | arpl                word ptr [ebx + 0x3c], ax
            //   31ed                 | mov                 edx, dword ptr [ebx + eax + 0x88]
            //   57                   | dec                 eax
            //   56                   | mov                 esi, eax
            //   31f6                 | mov                 eax, dword ptr [eax + 0x18]

    condition:
        7 of them and filesize < 164864
}