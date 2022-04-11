rule win_adylkuzz_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.adylkuzz."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.adylkuzz"
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
        $sequence_0 = { f7d0 2d064cd540 f5 f8 c1c002 663bea f8 }
            // n = 7, score = 100
            //   f7d0                 | not                 eax
            //   2d064cd540           | sub                 eax, 0x40d54c06
            //   f5                   | cmc                 
            //   f8                   | clc                 
            //   c1c002               | rol                 eax, 2
            //   663bea               | cmp                 bp, dx
            //   f8                   | clc                 

        $sequence_1 = { 33c3 85f3 66a94578 3ad2 8d80bff55da3 f6c144 f9 }
            // n = 7, score = 100
            //   33c3                 | xor                 eax, ebx
            //   85f3                 | test                ebx, esi
            //   66a94578             | test                ax, 0x7845
            //   3ad2                 | cmp                 dl, dl
            //   8d80bff55da3         | lea                 eax, dword ptr [eax - 0x5ca20a41]
            //   f6c144               | test                cl, 0x44
            //   f9                   | stc                 

        $sequence_2 = { 897304 e8???????? 894308 c7470403000000 83c410 5b 5e }
            // n = 7, score = 100
            //   897304               | mov                 dword ptr [ebx + 4], esi
            //   e8????????           |                     
            //   894308               | mov                 dword ptr [ebx + 8], eax
            //   c7470403000000       | mov                 dword ptr [edi + 4], 3
            //   83c410               | add                 esp, 0x10
            //   5b                   | pop                 ebx
            //   5e                   | pop                 esi

        $sequence_3 = { e8???????? 891c24 89442404 e8???????? 83ec80 b801000000 5b }
            // n = 7, score = 100
            //   e8????????           |                     
            //   891c24               | mov                 dword ptr [esp], ebx
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   e8????????           |                     
            //   83ec80               | sub                 esp, -0x80
            //   b801000000           | mov                 eax, 1
            //   5b                   | pop                 ebx

        $sequence_4 = { f7c4f2164208 8d5450d0 6681fefe5e 85ec 84c9 0f85c7ffffff 6a00 }
            // n = 7, score = 100
            //   f7c4f2164208         | test                esp, 0x84216f2
            //   8d5450d0             | lea                 edx, dword ptr [eax + edx*2 - 0x30]
            //   6681fefe5e           | cmp                 si, 0x5efe
            //   85ec                 | test                esp, ebp
            //   84c9                 | test                cl, cl
            //   0f85c7ffffff         | jne                 0xffffffcd
            //   6a00                 | push                0

        $sequence_5 = { f8 33d8 81fbe53a7e5c 663bf0 03f8 e9???????? 8be5 }
            // n = 7, score = 100
            //   f8                   | clc                 
            //   33d8                 | xor                 ebx, eax
            //   81fbe53a7e5c         | cmp                 ebx, 0x5c7e3ae5
            //   663bf0               | cmp                 si, ax
            //   03f8                 | add                 edi, eax
            //   e9????????           |                     
            //   8be5                 | mov                 esp, ebp

        $sequence_6 = { c3 53 83ec18 8b5c2420 89d8 e8???????? 8b4304 }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   53                   | push                ebx
            //   83ec18               | sub                 esp, 0x18
            //   8b5c2420             | mov                 ebx, dword ptr [esp + 0x20]
            //   89d8                 | mov                 eax, ebx
            //   e8????????           |                     
            //   8b4304               | mov                 eax, dword ptr [ebx + 4]

        $sequence_7 = { f7c412228151 33c3 66f7c47800 663bd9 3c61 f7d8 48 }
            // n = 7, score = 100
            //   f7c412228151         | test                esp, 0x51812212
            //   33c3                 | xor                 eax, ebx
            //   66f7c47800           | test                sp, 0x78
            //   663bd9               | cmp                 bx, cx
            //   3c61                 | cmp                 al, 0x61
            //   f7d8                 | neg                 eax
            //   48                   | dec                 eax

        $sequence_8 = { 89442418 8b07 c1e81c 83f809 0f8586000000 837f0c00 74ca }
            // n = 7, score = 100
            //   89442418             | mov                 dword ptr [esp + 0x18], eax
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   c1e81c               | shr                 eax, 0x1c
            //   83f809               | cmp                 eax, 9
            //   0f8586000000         | jne                 0x8c
            //   837f0c00             | cmp                 dword ptr [edi + 0xc], 0
            //   74ca                 | je                  0xffffffcc

        $sequence_9 = { e8???????? 89c6 eb17 3d0000000a beff7f0000 750b 89fa }
            // n = 7, score = 100
            //   e8????????           |                     
            //   89c6                 | mov                 esi, eax
            //   eb17                 | jmp                 0x19
            //   3d0000000a           | cmp                 eax, 0xa000000
            //   beff7f0000           | mov                 esi, 0x7fff
            //   750b                 | jne                 0xd
            //   89fa                 | mov                 edx, edi

    condition:
        7 of them and filesize < 6438912
}