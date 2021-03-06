rule win_zxxz_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.zxxz."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zxxz"
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
        $sequence_0 = { 51 6689442442 66894c2440 ff15???????? 6a10 }
            // n = 5, score = 100
            //   51                   | push                ecx
            //   6689442442           | mov                 word ptr [esp + 0x42], ax
            //   66894c2440           | mov                 word ptr [esp + 0x40], cx
            //   ff15????????         |                     
            //   6a10                 | push                0x10

        $sequence_1 = { 57 ff15???????? 8b35???????? 83c404 68???????? }
            // n = 5, score = 100
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   83c404               | add                 esp, 4
            //   68????????           |                     

        $sequence_2 = { eb36 68???????? 681c020000 68???????? ffd6 83c40c 68???????? }
            // n = 7, score = 100
            //   eb36                 | jmp                 0x38
            //   68????????           |                     
            //   681c020000           | push                0x21c
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   83c40c               | add                 esp, 0xc
            //   68????????           |                     

        $sequence_3 = { b8???????? f3a4 8bc8 8d4900 8a10 }
            // n = 5, score = 100
            //   b8????????           |                     
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8bc8                 | mov                 ecx, eax
            //   8d4900               | lea                 ecx, [ecx]
            //   8a10                 | mov                 dl, byte ptr [eax]

        $sequence_4 = { ff15???????? 33d2 68fe030000 52 8d84241a020000 50 668994241c020000 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   33d2                 | xor                 edx, edx
            //   68fe030000           | push                0x3fe
            //   52                   | push                edx
            //   8d84241a020000       | lea                 eax, [esp + 0x21a]
            //   50                   | push                eax
            //   668994241c020000     | mov                 word ptr [esp + 0x21c], dx

        $sequence_5 = { bb???????? ba???????? b9???????? e8???????? 83c404 e8???????? 803d????????00 }
            // n = 7, score = 100
            //   bb????????           |                     
            //   ba????????           |                     
            //   b9????????           |                     
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   e8????????           |                     
            //   803d????????00       |                     

        $sequence_6 = { 6a01 51 6689442442 66894c2440 ff15???????? 6a10 }
            // n = 6, score = 100
            //   6a01                 | push                1
            //   51                   | push                ecx
            //   6689442442           | mov                 word ptr [esp + 0x42], ax
            //   66894c2440           | mov                 word ptr [esp + 0x40], cx
            //   ff15????????         |                     
            //   6a10                 | push                0x10

        $sequence_7 = { 681c020000 68???????? ffd6 83c40c 68???????? ff15???????? }
            // n = 6, score = 100
            //   681c020000           | push                0x21c
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   83c40c               | add                 esp, 0xc
            //   68????????           |                     
            //   ff15????????         |                     

        $sequence_8 = { 8944243c ff15???????? 6a06 b902000000 }
            // n = 4, score = 100
            //   8944243c             | mov                 dword ptr [esp + 0x3c], eax
            //   ff15????????         |                     
            //   6a06                 | push                6
            //   b902000000           | mov                 ecx, 2

        $sequence_9 = { c3 81ecc4010000 a1???????? 33c4 898424bc010000 53 }
            // n = 6, score = 100
            //   c3                   | ret                 
            //   81ecc4010000         | sub                 esp, 0x1c4
            //   a1????????           |                     
            //   33c4                 | xor                 eax, esp
            //   898424bc010000       | mov                 dword ptr [esp + 0x1bc], eax
            //   53                   | push                ebx

    condition:
        7 of them and filesize < 4142080
}