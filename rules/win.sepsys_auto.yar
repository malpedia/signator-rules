rule win_sepsys_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.sepsys."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sepsys"
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
        $sequence_0 = { e8???????? 488b442428 488b4010 4803442430 488b4c2428 48894110 488b442428 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   488b442428           | dec                 eax
            //   488b4010             | mov                 ecx, dword ptr [ebp - 0x28]
            //   4803442430           | dec                 eax
            //   488b4c2428           | mov                 dword ptr [ebp - 0x30], edx
            //   48894110             | mov                 byte ptr [ebp + 0x56], 0
            //   488b442428           | dec                 eax

        $sequence_1 = { eb58 eb07 488b442448 eb4f 488b442438 488b4c2448 4803c8 }
            // n = 7, score = 400
            //   eb58                 | vmovdqa             xmm0, xmmword ptr [ebx + 0x4980]
            //   eb07                 | jmp                 0x472
            //   488b442448           | vmovdqa             xmm0, xmmword ptr [ebx + 0x4b50]
            //   eb4f                 | vmovdqa             xmmword ptr [ebx + 0x4b70], xmm0
            //   488b442438           | vmovdqa             xmm0, xmmword ptr [ebx + 0x4b70]
            //   488b4c2448           | vmovdqa             xmmword ptr [ebx + 0x4ac0], xmm0
            //   4803c8               | vmovdqa             xmm0, xmmword ptr [ebx + 0x4ac0]

        $sequence_2 = { e8???????? 4829c4 4889ce 0f57c0 0f29442470 0f29442460 0f29442450 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   4829c4               | lea                 ecx, [ebx + 0x3d60]
            //   4889ce               | dec                 eax
            //   0f57c0               | lea                 edx, [ebx + 0x3d80]
            //   0f29442470           | dec                 esp
            //   0f29442460           | lea                 eax, [ebx + 0x3da0]
            //   0f29442450           | vmovaps             ymmword ptr [ebx + 0xc20], ymm0

        $sequence_3 = { e8???????? 4883bd1003000000 0f84f6080000 e9???????? 31c0 89c1 488b9560050000 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   4883bd1003000000     | jmp                 0x4a
            //   0f84f6080000         | mov                 al, byte ptr [esp + 0x9f]
            //   e9????????           |                     
            //   31c0                 | shr                 al, 6
            //   89c1                 | vpshufd             ymm0, ymm0, 0x96
            //   488b9560050000       | vmovdqa             ymmword ptr [esp + 0xc0], ymm0

        $sequence_4 = { ff15???????? 89442448 8b4c2448 e8???????? 88442420 4883bc248000000000 7423 }
            // n = 7, score = 400
            //   ff15????????         |                     
            //   89442448             | ud2                 
            //   8b4c2448             | dec                 eax
            //   e8????????           |                     
            //   88442420             | lea                 ecx, [0xa3c46]
            //   4883bc248000000000     | ud2    
            //   7423                 | dec                 eax

        $sequence_5 = { eb22 488b542450 488b4c2448 e8???????? eb11 ff15???????? c7003f270000 }
            // n = 7, score = 400
            //   eb22                 | movzx               eax, byte ptr [esp + eax + 0xf0]
            //   488b542450           | cmp                 eax, 5
            //   488b4c2448           | mov                 eax, 7
            //   e8????????           |                     
            //   eb11                 | mov                 eax, 1
            //   ff15????????         |                     
            //   c7003f270000         | dec                 eax

        $sequence_6 = { f6c201 48898424d8000000 7505 e9???????? 488b842428010000 8b8c24e4000000 884804 }
            // n = 7, score = 400
            //   f6c201               | imul                eax, eax, 0x30
            //   48898424d8000000     | dec                 eax
            //   7505                 | mov                 ecx, dword ptr [esp + 0x2a0]
            //   e9????????           |                     
            //   488b842428010000     | dec                 eax
            //   8b8c24e4000000       | mov                 eax, dword ptr [esp + 0x2b0]
            //   884804               | dec                 eax

        $sequence_7 = { e8???????? eb00 488b45f8 488945f0 488b4db0 488b55f0 e8???????? }
            // n = 7, score = 400
            //   e8????????           |                     
            //   eb00                 | mov                 dword ptr [esp + 0x7b4], eax
            //   488b45f8             | jne                 0x60ff
            //   488945f0             | mov                 eax, dword ptr [esp + 0x7c4]
            //   488b4db0             | mov                 ecx, dword ptr [esp + 0x7b4]
            //   488b55f0             | shr                 eax, cl
            //   e8????????           |                     

        $sequence_8 = { e9???????? c685c701000000 e9???????? f685c701000001 74eb c685c701000000 488d4d08 }
            // n = 7, score = 400
            //   e9????????           |                     
            //   c685c701000000       | mov                 ecx, dword ptr [ebp - 0x48]
            //   e9????????           |                     
            //   f685c701000001       | dec                 eax
            //   74eb                 | mov                 dword ptr [ebp - 0x48], edx
            //   c685c701000000       | dec                 eax
            //   488d4d08             | mov                 dword ptr [ebp - 0x50], eax

        $sequence_9 = { e8???????? eb09 488975f0 e8???????? 0f0b ba01000000 4889f9 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   eb09                 | dec                 eax
            //   488975f0             | mov                 edx, dword ptr [esp + 0x58]
            //   e8????????           |                     
            //   0f0b                 | ud2                 
            //   ba01000000           | ud2                 
            //   4889f9               | dec                 eax

    condition:
        7 of them and filesize < 4538368
}