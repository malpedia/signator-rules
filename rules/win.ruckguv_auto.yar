rule win_ruckguv_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.ruckguv."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ruckguv"
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
        $sequence_0 = { 57 6a06 e8???????? be00080000 eb38 53 8d45f0 }
            // n = 7, score = 200
            //   57                   | push                edi
            //   6a06                 | push                6
            //   e8????????           |                     
            //   be00080000           | mov                 esi, 0x800
            //   eb38                 | jmp                 0x3a
            //   53                   | push                ebx
            //   8d45f0               | lea                 eax, [ebp - 0x10]

        $sequence_1 = { 53 8b5d08 8b433c 03c3 8b8080000000 85c0 }
            // n = 6, score = 200
            //   53                   | push                ebx
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   8b433c               | mov                 eax, dword ptr [ebx + 0x3c]
            //   03c3                 | add                 eax, ebx
            //   8b8080000000         | mov                 eax, dword ptr [eax + 0x80]
            //   85c0                 | test                eax, eax

        $sequence_2 = { 8345fc04 833e00 75bd 8b4720 83c714 85c0 7583 }
            // n = 7, score = 200
            //   8345fc04             | add                 dword ptr [ebp - 4], 4
            //   833e00               | cmp                 dword ptr [esi], 0
            //   75bd                 | jne                 0xffffffbf
            //   8b4720               | mov                 eax, dword ptr [edi + 0x20]
            //   83c714               | add                 edi, 0x14
            //   85c0                 | test                eax, eax
            //   7583                 | jne                 0xffffff85

        $sequence_3 = { 57 8d3c18 8b470c 85c0 747f 56 }
            // n = 6, score = 200
            //   57                   | push                edi
            //   8d3c18               | lea                 edi, [eax + ebx]
            //   8b470c               | mov                 eax, dword ptr [edi + 0xc]
            //   85c0                 | test                eax, eax
            //   747f                 | je                  0x81
            //   56                   | push                esi

        $sequence_4 = { fe45ff 881e 8810 660fb645ff 663b450c 7504 }
            // n = 6, score = 200
            //   fe45ff               | inc                 byte ptr [ebp - 1]
            //   881e                 | mov                 byte ptr [esi], bl
            //   8810                 | mov                 byte ptr [eax], dl
            //   660fb645ff           | movzx               ax, byte ptr [ebp - 1]
            //   663b450c             | cmp                 ax, word ptr [ebp + 0xc]
            //   7504                 | jne                 6

        $sequence_5 = { 03c3 50 e8???????? 59 894508 85c0 }
            // n = 6, score = 200
            //   03c3                 | add                 eax, ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   85c0                 | test                eax, eax

        $sequence_6 = { 8a4dff 888801010000 5f c9 c3 }
            // n = 5, score = 200
            //   8a4dff               | mov                 cl, byte ptr [ebp - 1]
            //   888801010000         | mov                 byte ptr [eax + 0x101], cl
            //   5f                   | pop                 edi
            //   c9                   | leave               
            //   c3                   | ret                 

        $sequence_7 = { 51 03c3 50 e8???????? 0fb74706 83c40c }
            // n = 6, score = 200
            //   51                   | push                ecx
            //   03c3                 | add                 eax, ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   0fb74706             | movzx               eax, word ptr [edi + 6]
            //   83c40c               | add                 esp, 0xc

        $sequence_8 = { 8d8594fbffff 50 8d858cf9ffff 68???????? }
            // n = 4, score = 200
            //   8d8594fbffff         | lea                 eax, [ebp - 0x46c]
            //   50                   | push                eax
            //   8d858cf9ffff         | lea                 eax, [ebp - 0x674]
            //   68????????           |                     

        $sequence_9 = { 83650800 33c0 663b4706 733c 8b4df8 eb03 }
            // n = 6, score = 200
            //   83650800             | and                 dword ptr [ebp + 8], 0
            //   33c0                 | xor                 eax, eax
            //   663b4706             | cmp                 ax, word ptr [edi + 6]
            //   733c                 | jae                 0x3e
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   eb03                 | jmp                 5

    condition:
        7 of them and filesize < 41024
}