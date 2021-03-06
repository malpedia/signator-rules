rule win_neutrino_pos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.neutrino_pos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.neutrino_pos"
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
        $sequence_0 = { ff75f8 ffd0 85c0 7415 ff75d8 e8???????? ff75dc }
            // n = 7, score = 200
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ffd0                 | call                eax
            //   85c0                 | test                eax, eax
            //   7415                 | je                  0x17
            //   ff75d8               | push                dword ptr [ebp - 0x28]
            //   e8????????           |                     
            //   ff75dc               | push                dword ptr [ebp - 0x24]

        $sequence_1 = { 58 6a66 66898564ffffff 58 6a65 66898566ffffff }
            // n = 6, score = 200
            //   58                   | pop                 eax
            //   6a66                 | push                0x66
            //   66898564ffffff       | mov                 word ptr [ebp - 0x9c], ax
            //   58                   | pop                 eax
            //   6a65                 | push                0x65
            //   66898566ffffff       | mov                 word ptr [ebp - 0x9a], ax

        $sequence_2 = { 668945fe 8d854cffffff 68b4000000 50 66894d8e 66894d90 66894d92 }
            // n = 7, score = 200
            //   668945fe             | mov                 word ptr [ebp - 2], ax
            //   8d854cffffff         | lea                 eax, [ebp - 0xb4]
            //   68b4000000           | push                0xb4
            //   50                   | push                eax
            //   66894d8e             | mov                 word ptr [ebp - 0x72], cx
            //   66894d90             | mov                 word ptr [ebp - 0x70], cx
            //   66894d92             | mov                 word ptr [ebp - 0x6e], cx

        $sequence_3 = { c9 c3 55 8bec 83ec1c 834dfcff 56 }
            // n = 7, score = 200
            //   c9                   | leave               
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec1c               | sub                 esp, 0x1c
            //   834dfcff             | or                  dword ptr [ebp - 4], 0xffffffff
            //   56                   | push                esi

        $sequence_4 = { 59 5d c3 55 8bec 687ea2cc85 6a01 }
            // n = 7, score = 200
            //   59                   | pop                 ecx
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   687ea2cc85           | push                0x85cca27e
            //   6a01                 | push                1

        $sequence_5 = { 8bc1 6689854effffff 58 6a73 }
            // n = 4, score = 200
            //   8bc1                 | mov                 eax, ecx
            //   6689854effffff       | mov                 word ptr [ebp - 0xb2], ax
            //   58                   | pop                 eax
            //   6a73                 | push                0x73

        $sequence_6 = { 83c8ff a5 59 3945d8 7463 0fb74314 8d441818 }
            // n = 7, score = 200
            //   83c8ff               | or                  eax, 0xffffffff
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   59                   | pop                 ecx
            //   3945d8               | cmp                 dword ptr [ebp - 0x28], eax
            //   7463                 | je                  0x65
            //   0fb74314             | movzx               eax, word ptr [ebx + 0x14]
            //   8d441818             | lea                 eax, [eax + ebx + 0x18]

        $sequence_7 = { 59 56 56 56 56 ffd0 }
            // n = 6, score = 200
            //   59                   | pop                 ecx
            //   56                   | push                esi
            //   56                   | push                esi
            //   56                   | push                esi
            //   56                   | push                esi
            //   ffd0                 | call                eax

        $sequence_8 = { 682661fbb6 6a01 e8???????? 83c414 8d4dd4 51 }
            // n = 6, score = 200
            //   682661fbb6           | push                0xb6fb6126
            //   6a01                 | push                1
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   8d4dd4               | lea                 ecx, [ebp - 0x2c]
            //   51                   | push                ecx

        $sequence_9 = { 8d75a8 a5 a5 8b08 a5 83ec10 }
            // n = 6, score = 200
            //   8d75a8               | lea                 esi, [ebp - 0x58]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   83ec10               | sub                 esp, 0x10

    condition:
        7 of them and filesize < 188416
}