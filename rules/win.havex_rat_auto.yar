rule win_havex_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.havex_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.havex_rat"
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
        $sequence_0 = { c645fc01 e8???????? 68???????? 8d4e3c c645fc02 e8???????? 68???????? }
            // n = 7, score = 100
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   e8????????           |                     
            //   68????????           |                     
            //   8d4e3c               | lea                 ecx, dword ptr [esi + 0x3c]
            //   c645fc02             | mov                 byte ptr [ebp - 4], 2
            //   e8????????           |                     
            //   68????????           |                     

        $sequence_1 = { 72d2 5e 83fa21 730c 6a21 59 2bca }
            // n = 7, score = 100
            //   72d2                 | jb                  0xffffffd4
            //   5e                   | pop                 esi
            //   83fa21               | cmp                 edx, 0x21
            //   730c                 | jae                 0xe
            //   6a21                 | push                0x21
            //   59                   | pop                 ecx
            //   2bca                 | sub                 ecx, edx

        $sequence_2 = { 660fb600 8b8b500c0000 66890451 eb0c 0fb600 8b8b4c0c0000 890491 }
            // n = 7, score = 100
            //   660fb600             | movzx               ax, byte ptr [eax]
            //   8b8b500c0000         | mov                 ecx, dword ptr [ebx + 0xc50]
            //   66890451             | mov                 word ptr [ecx + edx*2], ax
            //   eb0c                 | jmp                 0xe
            //   0fb600               | movzx               eax, byte ptr [eax]
            //   8b8b4c0c0000         | mov                 ecx, dword ptr [ebx + 0xc4c]
            //   890491               | mov                 dword ptr [ecx + edx*4], eax

        $sequence_3 = { 8b4c2414 3bce 7405 e8???????? 56 57 8d4c2474 }
            // n = 7, score = 100
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   3bce                 | cmp                 ecx, esi
            //   7405                 | je                  7
            //   e8????????           |                     
            //   56                   | push                esi
            //   57                   | push                edi
            //   8d4c2474             | lea                 ecx, dword ptr [esp + 0x74]

        $sequence_4 = { 683f000f00 53 ff75ec 53 50 6801000080 }
            // n = 6, score = 100
            //   683f000f00           | push                0xf003f
            //   53                   | push                ebx
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   6801000080           | push                0x80000001

        $sequence_5 = { 0f87ad090000 ff2485a3420310 33c0 838de8fdffffff 898594fdffff 8985a8fdffff 8985ccfdffff }
            // n = 7, score = 100
            //   0f87ad090000         | ja                  0x9b3
            //   ff2485a3420310       | jmp                 dword ptr [eax*4 + 0x100342a3]
            //   33c0                 | xor                 eax, eax
            //   838de8fdffffff       | or                  dword ptr [ebp - 0x218], 0xffffffff
            //   898594fdffff         | mov                 dword ptr [ebp - 0x26c], eax
            //   8985a8fdffff         | mov                 dword ptr [ebp - 0x258], eax
            //   8985ccfdffff         | mov                 dword ptr [ebp - 0x234], eax

        $sequence_6 = { 885dd8 ff75d8 8b1e 8d45d8 50 8bce ff5304 }
            // n = 7, score = 100
            //   885dd8               | mov                 byte ptr [ebp - 0x28], bl
            //   ff75d8               | push                dword ptr [ebp - 0x28]
            //   8b1e                 | mov                 ebx, dword ptr [esi]
            //   8d45d8               | lea                 eax, dword ptr [ebp - 0x28]
            //   50                   | push                eax
            //   8bce                 | mov                 ecx, esi
            //   ff5304               | call                dword ptr [ebx + 4]

        $sequence_7 = { 8b45f0 e8???????? c3 6a1c b8???????? e8???????? 8b450c }
            // n = 7, score = 100
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   e8????????           |                     
            //   c3                   | ret                 
            //   6a1c                 | push                0x1c
            //   b8????????           |                     
            //   e8????????           |                     
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_8 = { 59 e8???????? e8???????? 33db 385c2414 0f849f000000 57 }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   e8????????           |                     
            //   e8????????           |                     
            //   33db                 | xor                 ebx, ebx
            //   385c2414             | cmp                 byte ptr [esp + 0x14], bl
            //   0f849f000000         | je                  0xa5
            //   57                   | push                edi

        $sequence_9 = { ff45e4 837de410 7c88 ff45f0 8b45f0 83f810 7d10 }
            // n = 7, score = 100
            //   ff45e4               | inc                 dword ptr [ebp - 0x1c]
            //   837de410             | cmp                 dword ptr [ebp - 0x1c], 0x10
            //   7c88                 | jl                  0xffffff8a
            //   ff45f0               | inc                 dword ptr [ebp - 0x10]
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   83f810               | cmp                 eax, 0x10
            //   7d10                 | jge                 0x12

    condition:
        7 of them and filesize < 892928
}