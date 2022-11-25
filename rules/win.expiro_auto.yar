rule win_expiro_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.expiro."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.expiro"
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
        $sequence_0 = { 48 8d0df8320000 e8???????? ff15???????? 48 8bc8 }
            // n = 6, score = 100
            //   48                   | dec                 eax
            //   8d0df8320000         | lea                 ecx, [0x32f8]
            //   e8????????           |                     
            //   ff15????????         |                     
            //   48                   | dec                 eax
            //   8bc8                 | mov                 ecx, eax

        $sequence_1 = { 0f879f000000 ff248514184000 8bd6 8bcb e8???????? 56 53 }
            // n = 7, score = 100
            //   0f879f000000         | ja                  0xa5
            //   ff248514184000       | jmp                 dword ptr [eax*4 + 0x401814]
            //   8bd6                 | mov                 edx, esi
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   56                   | push                esi
            //   53                   | push                ebx

        $sequence_2 = { 662b4718 6603c8 66894c2420 40 }
            // n = 4, score = 100
            //   662b4718             | sub                 ax, word ptr [edi + 0x18]
            //   6603c8               | add                 cx, ax
            //   66894c2420           | mov                 word ptr [esp + 0x20], cx
            //   40                   | inc                 eax

        $sequence_3 = { b865477241 66f2af 48 f7d1 48 8d6901 33c9 }
            // n = 7, score = 100
            //   b865477241           | mov                 eax, 0x41724765
            //   66f2af               | repne scasd         eax, dword ptr es:[edi]
            //   48                   | dec                 eax
            //   f7d1                 | not                 ecx
            //   48                   | dec                 eax
            //   8d6901               | lea                 ebp, [ecx + 1]
            //   33c9                 | xor                 ecx, ecx

        $sequence_4 = { 895d00 895c2444 66c74424480001 895c243c 66c74424400005 ff15???????? 85c0 }
            // n = 7, score = 100
            //   895d00               | mov                 dword ptr [ebp], ebx
            //   895c2444             | mov                 dword ptr [esp + 0x44], ebx
            //   66c74424480001       | mov                 word ptr [esp + 0x48], 0x100
            //   895c243c             | mov                 dword ptr [esp + 0x3c], ebx
            //   66c74424400005       | mov                 word ptr [esp + 0x40], 0x500
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_5 = { 3bfb 7507 68???????? eb05 68???????? e8???????? 83c404 }
            // n = 7, score = 100
            //   3bfb                 | cmp                 edi, ebx
            //   7507                 | jne                 9
            //   68????????           |                     
            //   eb05                 | jmp                 7
            //   68????????           |                     
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_6 = { 8d442414 64a300000000 8b6c242c 8b742424 c744241000000000 33c0 c7461407000000 }
            // n = 7, score = 100
            //   8d442414             | lea                 eax, [esp + 0x14]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8b6c242c             | mov                 ebp, dword ptr [esp + 0x2c]
            //   8b742424             | mov                 esi, dword ptr [esp + 0x24]
            //   c744241000000000     | mov                 dword ptr [esp + 0x10], 0
            //   33c0                 | xor                 eax, eax
            //   c7461407000000       | mov                 dword ptr [esi + 0x14], 7

        $sequence_7 = { 84c0 740d 48 8b4f50 48 8d5738 e8???????? }
            // n = 7, score = 100
            //   84c0                 | test                al, al
            //   740d                 | je                  0xf
            //   48                   | dec                 eax
            //   8b4f50               | mov                 ecx, dword ptr [edi + 0x50]
            //   48                   | dec                 eax
            //   8d5738               | lea                 edx, [edi + 0x38]
            //   e8????????           |                     

        $sequence_8 = { c1f905 8b0c8d409d4100 c1e006 8d44010c 50 ff15???????? }
            // n = 6, score = 100
            //   c1f905               | sar                 ecx, 5
            //   8b0c8d409d4100       | mov                 ecx, dword ptr [ecx*4 + 0x419d40]
            //   c1e006               | shl                 eax, 6
            //   8d44010c             | lea                 eax, [ecx + eax + 0xc]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_9 = { 302406 082b 06 0105???????? 8618 687474703a 2f }
            // n = 7, score = 100
            //   302406               | xor                 byte ptr [esi + eax], ah
            //   082b                 | or                  byte ptr [ebx], ch
            //   06                   | push                es
            //   0105????????         |                     
            //   8618                 | xchg                byte ptr [eax], bl
            //   687474703a           | push                0x3a707474
            //   2f                   | das                 

    condition:
        7 of them and filesize < 3776512
}