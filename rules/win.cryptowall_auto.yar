rule win_cryptowall_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.cryptowall."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cryptowall"
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
        $sequence_0 = { 52 e8???????? 83c408 8b0d???????? 894150 }
            // n = 5, score = 2100
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b0d????????         |                     
            //   894150               | mov                 dword ptr [ecx + 0x50], eax

        $sequence_1 = { c745fc00000000 c745f400000000 8d45f4 50 8d4dfc 51 8b5508 }
            // n = 7, score = 2100
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   8d4dfc               | lea                 ecx, [ebp - 4]
            //   51                   | push                ecx
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]

        $sequence_2 = { 8b4d10 8d540902 52 8b450c 50 8b4d08 51 }
            // n = 7, score = 2100
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   8d540902             | lea                 edx, [ecx + ecx + 2]
            //   52                   | push                edx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   51                   | push                ecx

        $sequence_3 = { 668955e8 b874000000 668945ea b965000000 66894dec ba6d000000 }
            // n = 6, score = 2100
            //   668955e8             | mov                 word ptr [ebp - 0x18], dx
            //   b874000000           | mov                 eax, 0x74
            //   668945ea             | mov                 word ptr [ebp - 0x16], ax
            //   b965000000           | mov                 ecx, 0x65
            //   66894dec             | mov                 word ptr [ebp - 0x14], cx
            //   ba6d000000           | mov                 edx, 0x6d

        $sequence_4 = { 8b55f0 52 e8???????? 8b00 ffd0 }
            // n = 5, score = 2100
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   52                   | push                edx
            //   e8????????           |                     
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   ffd0                 | call                eax

        $sequence_5 = { e8???????? 83c408 8b0d???????? 894144 }
            // n = 4, score = 2100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b0d????????         |                     
            //   894144               | mov                 dword ptr [ecx + 0x44], eax

        $sequence_6 = { 7505 83c8ff eb04 eb9b }
            // n = 4, score = 2100
            //   7505                 | jne                 7
            //   83c8ff               | or                  eax, 0xffffffff
            //   eb04                 | jmp                 6
            //   eb9b                 | jmp                 0xffffff9d

        $sequence_7 = { 83c408 99 b91a000000 f7f9 83c261 8b45f4 }
            // n = 6, score = 2100
            //   83c408               | add                 esp, 8
            //   99                   | cdq                 
            //   b91a000000           | mov                 ecx, 0x1a
            //   f7f9                 | idiv                ecx
            //   83c261               | add                 edx, 0x61
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_8 = { e9???????? c745fc00000000 8d45fc 50 e8???????? }
            // n = 5, score = 2100
            //   e9????????           |                     
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_9 = { b861000000 668945ee b963000000 66894df0 ba68000000 }
            // n = 5, score = 2100
            //   b861000000           | mov                 eax, 0x61
            //   668945ee             | mov                 word ptr [ebp - 0x12], ax
            //   b963000000           | mov                 ecx, 0x63
            //   66894df0             | mov                 word ptr [ebp - 0x10], cx
            //   ba68000000           | mov                 edx, 0x68

    condition:
        7 of them and filesize < 417792
}