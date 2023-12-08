rule win_breakthrough_loader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.breakthrough_loader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.breakthrough_loader"
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
        $sequence_0 = { 7e2a 8b7df8 660f1f840000000000 0fb7444e08 a900300000 740a }
            // n = 6, score = 100
            //   7e2a                 | jle                 0x2c
            //   8b7df8               | mov                 edi, dword ptr [ebp - 8]
            //   660f1f840000000000     | nop    word ptr [eax + eax]
            //   0fb7444e08           | movzx               eax, word ptr [esi + ecx*2 + 8]
            //   a900300000           | test                eax, 0x3000
            //   740a                 | je                  0xc

        $sequence_1 = { 5d c3 8b4d14 890e 8b4d24 }
            // n = 5, score = 100
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]
            //   890e                 | mov                 dword ptr [esi], ecx
            //   8b4d24               | mov                 ecx, dword ptr [ebp + 0x24]

        $sequence_2 = { 8945e8 8945f8 8b4508 56 be???????? c745eca07d4400 57 }
            // n = 7, score = 100
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   56                   | push                esi
            //   be????????           |                     
            //   c745eca07d4400       | mov                 dword ptr [ebp - 0x14], 0x447da0
            //   57                   | push                edi

        $sequence_3 = { 8b450c 0fb68401d86a4400 c1e804 5d }
            // n = 4, score = 100
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   0fb68401d86a4400     | movzx               eax, byte ptr [ecx + eax + 0x446ad8]
            //   c1e804               | shr                 eax, 4
            //   5d                   | pop                 ebp

        $sequence_4 = { 85f6 742d 83f910 8d442420 0f43442420 881418 }
            // n = 6, score = 100
            //   85f6                 | test                esi, esi
            //   742d                 | je                  0x2f
            //   83f910               | cmp                 ecx, 0x10
            //   8d442420             | lea                 eax, [esp + 0x20]
            //   0f43442420           | cmovae              eax, dword ptr [esp + 0x20]
            //   881418               | mov                 byte ptr [eax + ebx], dl

        $sequence_5 = { e8???????? 33c0 c744242c07000000 8d8c2490000000 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   c744242c07000000     | mov                 dword ptr [esp + 0x2c], 7
            //   8d8c2490000000       | lea                 ecx, [esp + 0x90]

        $sequence_6 = { 8bc7 83e03f 6bc830 8b049540354500 f644082801 7421 57 }
            // n = 7, score = 100
            //   8bc7                 | mov                 eax, edi
            //   83e03f               | and                 eax, 0x3f
            //   6bc830               | imul                ecx, eax, 0x30
            //   8b049540354500       | mov                 eax, dword ptr [edx*4 + 0x453540]
            //   f644082801           | test                byte ptr [eax + ecx + 0x28], 1
            //   7421                 | je                  0x23
            //   57                   | push                edi

        $sequence_7 = { 83e03f 6bc030 59 59 0304bd40354500 5f eb05 }
            // n = 7, score = 100
            //   83e03f               | and                 eax, 0x3f
            //   6bc030               | imul                eax, eax, 0x30
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   0304bd40354500       | add                 eax, dword ptr [edi*4 + 0x453540]
            //   5f                   | pop                 edi
            //   eb05                 | jmp                 7

        $sequence_8 = { 8b0cbd40354500 83c410 8b7de8 89440f20 8bc6 }
            // n = 5, score = 100
            //   8b0cbd40354500       | mov                 ecx, dword ptr [edi*4 + 0x453540]
            //   83c410               | add                 esp, 0x10
            //   8b7de8               | mov                 edi, dword ptr [ebp - 0x18]
            //   89440f20             | mov                 dword ptr [edi + ecx + 0x20], eax
            //   8bc6                 | mov                 eax, esi

        $sequence_9 = { 8b3e 8d0417 3bd0 731d 8d47ff 8906 8b4b20 }
            // n = 7, score = 100
            //   8b3e                 | mov                 edi, dword ptr [esi]
            //   8d0417               | lea                 eax, [edi + edx]
            //   3bd0                 | cmp                 edx, eax
            //   731d                 | jae                 0x1f
            //   8d47ff               | lea                 eax, [edi - 1]
            //   8906                 | mov                 dword ptr [esi], eax
            //   8b4b20               | mov                 ecx, dword ptr [ebx + 0x20]

    condition:
        7 of them and filesize < 753664
}