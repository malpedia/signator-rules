rule win_thunker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.thunker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.thunker"
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
        $sequence_0 = { ff35???????? e8???????? 6a00 6888130000 68e7710000 }
            // n = 5, score = 100
            //   ff35????????         |                     
            //   e8????????           |                     
            //   6a00                 | push                0
            //   6888130000           | push                0x1388
            //   68e7710000           | push                0x71e7

        $sequence_1 = { 8d8544edffff 50 e8???????? 8985c4edffff 8b400c 8b00 8b00 }
            // n = 7, score = 100
            //   8d8544edffff         | lea                 eax, dword ptr [ebp - 0x12bc]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8985c4edffff         | mov                 dword ptr [ebp - 0x123c], eax
            //   8b400c               | mov                 eax, dword ptr [eax + 0xc]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8b00                 | mov                 eax, dword ptr [eax]

        $sequence_2 = { 39f8 97 0f94c0 97 }
            // n = 4, score = 100
            //   39f8                 | cmp                 eax, edi
            //   97                   | xchg                eax, edi
            //   0f94c0               | sete                al
            //   97                   | xchg                eax, edi

        $sequence_3 = { 50 ffb5e0edffff e8???????? 89c6 83feff 7456 8d85fcfeffff }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ffb5e0edffff         | push                dword ptr [ebp - 0x1220]
            //   e8????????           |                     
            //   89c6                 | mov                 esi, eax
            //   83feff               | cmp                 esi, -1
            //   7456                 | je                  0x58
            //   8d85fcfeffff         | lea                 eax, dword ptr [ebp - 0x104]

        $sequence_4 = { 83c40c c685f0edffff00 c685f1edffff5a 6a00 6a08 8d85f0edffff }
            // n = 6, score = 100
            //   83c40c               | add                 esp, 0xc
            //   c685f0edffff00       | mov                 byte ptr [ebp - 0x1210], 0
            //   c685f1edffff5a       | mov                 byte ptr [ebp - 0x120f], 0x5a
            //   6a00                 | push                0
            //   6a08                 | push                8
            //   8d85f0edffff         | lea                 eax, dword ptr [ebp - 0x1210]

        $sequence_5 = { f3a5 6a0a 8d45b0 50 68aa280d00 e8???????? 8d45b0 }
            // n = 7, score = 100
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   6a0a                 | push                0xa
            //   8d45b0               | lea                 eax, dword ptr [ebp - 0x50]
            //   50                   | push                eax
            //   68aa280d00           | push                0xd28aa
            //   e8????????           |                     
            //   8d45b0               | lea                 eax, dword ptr [ebp - 0x50]

        $sequence_6 = { c3 55 89e5 83ec6c 56 57 8b450c }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   83ec6c               | sub                 esp, 0x6c
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_7 = { e8???????? 89c6 83feff 7456 8d85fcfeffff 50 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   89c6                 | mov                 esi, eax
            //   83feff               | cmp                 esi, -1
            //   7456                 | je                  0x58
            //   8d85fcfeffff         | lea                 eax, dword ptr [ebp - 0x104]
            //   50                   | push                eax

        $sequence_8 = { 55 89e5 81ec20020000 53 56 57 ff7508 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   81ec20020000         | sub                 esp, 0x220
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_9 = { 89df 31c0 f9 19c9 }
            // n = 4, score = 100
            //   89df                 | mov                 edi, ebx
            //   31c0                 | xor                 eax, eax
            //   f9                   | stc                 
            //   19c9                 | sbb                 ecx, ecx

    condition:
        7 of them and filesize < 73728
}