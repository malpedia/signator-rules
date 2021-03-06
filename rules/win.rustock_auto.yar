rule win_rustock_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.rustock."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rustock"
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
        $sequence_0 = { a3???????? ffd6 6879030000 57 a3???????? ffd6 }
            // n = 6, score = 100
            //   a3????????           |                     
            //   ffd6                 | call                esi
            //   6879030000           | push                0x379
            //   57                   | push                edi
            //   a3????????           |                     
            //   ffd6                 | call                esi

        $sequence_1 = { 1e 4e 16 da81e53a558c b9157556b8 af 44 }
            // n = 7, score = 100
            //   1e                   | push                ds
            //   4e                   | dec                 esi
            //   16                   | push                ss
            //   da81e53a558c         | fiadd               dword ptr [ecx - 0x73aac51b]
            //   b9157556b8           | mov                 ecx, 0xb8567515
            //   af                   | scasd               eax, dword ptr es:[edi]
            //   44                   | inc                 esp

        $sequence_2 = { 22a999155d2e ad 282cf4 d7 846be6 5d }
            // n = 6, score = 100
            //   22a999155d2e         | and                 ch, byte ptr [ecx + 0x2e5d1599]
            //   ad                   | lodsd               eax, dword ptr [esi]
            //   282cf4               | sub                 byte ptr [esp + esi*8], ch
            //   d7                   | xlatb               
            //   846be6               | test                byte ptr [ebx - 0x1a], ch
            //   5d                   | pop                 ebp

        $sequence_3 = { 8b3424 83c404 e9???????? 83ec04 892c24 83ec04 893424 }
            // n = 7, score = 100
            //   8b3424               | mov                 esi, dword ptr [esp]
            //   83c404               | add                 esp, 4
            //   e9????????           |                     
            //   83ec04               | sub                 esp, 4
            //   892c24               | mov                 dword ptr [esp], ebp
            //   83ec04               | sub                 esp, 4
            //   893424               | mov                 dword ptr [esp], esi

        $sequence_4 = { 5b 5f c3 ff35???????? e8???????? 8325????????00 }
            // n = 6, score = 100
            //   5b                   | pop                 ebx
            //   5f                   | pop                 edi
            //   c3                   | ret                 
            //   ff35????????         |                     
            //   e8????????           |                     
            //   8325????????00       |                     

        $sequence_5 = { 01d8 8b0490 01d8 56 }
            // n = 4, score = 100
            //   01d8                 | add                 eax, ebx
            //   8b0490               | mov                 eax, dword ptr [eax + edx*4]
            //   01d8                 | add                 eax, ebx
            //   56                   | push                esi

        $sequence_6 = { 7409 ff75d0 e8???????? 59 395de0 7409 }
            // n = 6, score = 100
            //   7409                 | je                  0xb
            //   ff75d0               | push                dword ptr [ebp - 0x30]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   395de0               | cmp                 dword ptr [ebp - 0x20], ebx
            //   7409                 | je                  0xb

        $sequence_7 = { 7506 53 e8???????? 6804010000 8d85fcfeffff 50 6a00 }
            // n = 7, score = 100
            //   7506                 | jne                 8
            //   53                   | push                ebx
            //   e8????????           |                     
            //   6804010000           | push                0x104
            //   8d85fcfeffff         | lea                 eax, [ebp - 0x104]
            //   50                   | push                eax
            //   6a00                 | push                0

        $sequence_8 = { bdec56d78d ee b380 c055849c }
            // n = 4, score = 100
            //   bdec56d78d           | mov                 ebp, 0x8dd756ec
            //   ee                   | out                 dx, al
            //   b380                 | mov                 bl, 0x80
            //   c055849c             | rcl                 byte ptr [ebp - 0x7c], 0x9c

        $sequence_9 = { eb16 8bcf 8bf1 c1e902 33c0 }
            // n = 5, score = 100
            //   eb16                 | jmp                 0x18
            //   8bcf                 | mov                 ecx, edi
            //   8bf1                 | mov                 esi, ecx
            //   c1e902               | shr                 ecx, 2
            //   33c0                 | xor                 eax, eax

    condition:
        7 of them and filesize < 565248
}