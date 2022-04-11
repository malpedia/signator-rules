rule win_yahoyah_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.yahoyah."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.yahoyah"
        malpedia_rule_date = "20220405"
        malpedia_hash = "ecd38294bd47d5589be5cd5490dc8bb4804afc2a"
        malpedia_version = ""
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
        $sequence_0 = { ff15???????? 6a02 53 6af0 }
            // n = 4, score = 400
            //   ff15????????         |                     
            //   6a02                 | push                2
            //   53                   | push                ebx
            //   6af0                 | push                -0x10

        $sequence_1 = { ff15???????? 6a2e 68???????? e8???????? }
            // n = 4, score = 400
            //   ff15????????         |                     
            //   6a2e                 | push                0x2e
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_2 = { ff15???????? 6a3a 56 e8???????? 8bf0 83c410 }
            // n = 6, score = 300
            //   ff15????????         |                     
            //   6a3a                 | push                0x3a
            //   56                   | push                esi
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c410               | add                 esp, 0x10

        $sequence_3 = { 53 56 53 ff15???????? 68d0070000 ff15???????? }
            // n = 6, score = 300
            //   53                   | push                ebx
            //   56                   | push                esi
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   68d0070000           | push                0x7d0
            //   ff15????????         |                     

        $sequence_4 = { ff15???????? 85c0 7501 c3 56 }
            // n = 5, score = 300
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7501                 | jne                 3
            //   c3                   | ret                 
            //   56                   | push                esi

        $sequence_5 = { 23d1 52 8bd0 c1ea18 52 }
            // n = 5, score = 300
            //   23d1                 | and                 edx, ecx
            //   52                   | push                edx
            //   8bd0                 | mov                 edx, eax
            //   c1ea18               | shr                 edx, 0x18
            //   52                   | push                edx

        $sequence_6 = { 0fb7c8 b8???????? 50 50 }
            // n = 4, score = 300
            //   0fb7c8               | movzx               ecx, ax
            //   b8????????           |                     
            //   50                   | push                eax
            //   50                   | push                eax

        $sequence_7 = { 53 50 e8???????? 83c418 6a02 53 6840feffff }
            // n = 7, score = 300
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   6a02                 | push                2
            //   53                   | push                ebx
            //   6840feffff           | push                0xfffffe40

        $sequence_8 = { 68???????? 6890ef0000 68???????? 6a60 }
            // n = 4, score = 300
            //   68????????           |                     
            //   6890ef0000           | push                0xef90
            //   68????????           |                     
            //   6a60                 | push                0x60

        $sequence_9 = { 33db 53 68???????? 6a03 53 6a01 }
            // n = 6, score = 300
            //   33db                 | xor                 ebx, ebx
            //   53                   | push                ebx
            //   68????????           |                     
            //   6a03                 | push                3
            //   53                   | push                ebx
            //   6a01                 | push                1

        $sequence_10 = { 6a1a 50 e8???????? bf???????? }
            // n = 4, score = 300
            //   6a1a                 | push                0x1a
            //   50                   | push                eax
            //   e8????????           |                     
            //   bf????????           |                     

        $sequence_11 = { 8d85fcd7ffff 50 e8???????? 59 85c0 }
            // n = 5, score = 300
            //   8d85fcd7ffff         | lea                 eax, dword ptr [ebp - 0x2804]
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax

        $sequence_12 = { 90 90 68add13441 ffb53ffbffff 6a00 }
            // n = 5, score = 100
            //   90                   | nop                 
            //   90                   | nop                 
            //   68add13441           | push                0x4134d1ad
            //   ffb53ffbffff         | push                dword ptr [ebp - 0x4c1]
            //   6a00                 | push                0

        $sequence_13 = { 90 90 33c9 33c0 648b3530000000 8b760c 8b761c }
            // n = 7, score = 100
            //   90                   | nop                 
            //   90                   | nop                 
            //   33c9                 | xor                 ecx, ecx
            //   33c0                 | xor                 eax, eax
            //   648b3530000000       | mov                 esi, dword ptr fs:[0x30]
            //   8b760c               | mov                 esi, dword ptr [esi + 0xc]
            //   8b761c               | mov                 esi, dword ptr [esi + 0x1c]

    condition:
        7 of them and filesize < 483328
}