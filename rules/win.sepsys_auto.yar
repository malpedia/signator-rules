rule win_sepsys_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.sepsys."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sepsys"
        malpedia_rule_date = "20211007"
        malpedia_hash = "e5b790e0f888f252d49063a1251ca60ec2832535"
        malpedia_version = "20211008"
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
        $sequence_0 = { e8???????? ebf0 48837d7000 741d eb30 488d4d50 e8???????? }
            // n = 7, score = 400
            //   e8????????           |                     
            //   ebf0                 | mov                 dword ptr [esp + 0x80], 1
            //   48837d7000           | cmp                 dword ptr [esp + 0x80], 0
            //   741d                 | je                  0x2db
            //   eb30                 | je                  0x2d3
            //   488d4d50             | jmp                 0x306
            //   e8????????           |                     

        $sequence_1 = { e8???????? 89442464 488b842490010000 b907000000 4839c1 0f92c2 f6c201 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   89442464             | mov                 ecx, dword ptr [eax + 8]
            //   488b842490010000     | inc                 sp
            //   b907000000           | mov                 dword ptr [esp + 0x60], ecx
            //   4839c1               | inc                 sp
            //   0f92c2               | mov                 dword ptr [esp + 0x5c], ecx
            //   f6c201               | inc                 bp

        $sequence_2 = { e8???????? 488b442448 4889442438 488b442450 4889442440 488b442440 4889442478 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   488b442448           | movdqa              xmmword ptr [ebx + 0x33d0], xmm0
            //   4889442438           | dec                 eax
            //   488b442450           | lea                 ecx, dword ptr [ebx + 0x33b0]
            //   4889442440           | dec                 eax
            //   488b442440           | lea                 edx, dword ptr [ebx + 0x33c0]
            //   4889442478           | dec                 esp

        $sequence_3 = { e9???????? 488b8424e8010000 488b8c24f0010000 4889842428020000 48898c2430020000 488b842428020000 488b8c2430020000 }
            // n = 7, score = 400
            //   e9????????           |                     
            //   488b8424e8010000     | dec                 eax
            //   488b8c24f0010000     | xor                 ecx, esp
            //   4889842428020000     | je                  0x1f85
            //   48898c2430020000     | mov                 edx, 5
            //   488b842428020000     | dec                 eax
            //   488b8c2430020000     | mov                 ecx, dword ptr [esp + 0x28]

        $sequence_4 = { e8???????? 488945d0 eb00 488b8538030000 488b4dd0 48894808 488b8538030000 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   488945d0             | dec                 eax
            //   eb00                 | mov                 ecx, ebx
            //   488b8538030000       | pop                 ebp
            //   488b4dd0             | ret                 
            //   48894808             | dec                 esp
            //   488b8538030000       | add                 edi, dword ptr [ebp - 0x10]

        $sequence_5 = { eb00 488b4528 4883f800 744b 488b8508010000 488b00 48898520010000 }
            // n = 7, score = 400
            //   eb00                 | je                  0xc3c
            //   488b4528             | jmp                 0xc12
            //   4883f800             | dec                 eax
            //   744b                 | mov                 eax, dword ptr [ebp + 0x3e0]
            //   488b8508010000       | dec                 eax
            //   488b00               | sub                 eax, 0x20
            //   48898520010000       | je                  0xc49

        $sequence_6 = { eb02 31f6 4c897c2420 48c744243000000000 c744242800080000 89d9 4889f2 }
            // n = 7, score = 400
            //   eb02                 | dec                 eax
            //   31f6                 | lea                 ecx, dword ptr [0x199c64]
            //   4c897c2420           | ud2                 
            //   48c744243000000000     | xor    eax, eax
            //   c744242800080000     | test                al, 1
            //   89d9                 | jne                 0x1b11
            //   4889f2               | jmp                 0x1b1f

        $sequence_7 = { c744243001000000 488b8424a0000000 4889442448 48837c247000 7666 8b442440 4889842420010000 }
            // n = 7, score = 400
            //   c744243001000000     | mov                 dword ptr [ebp + 0x878], edx
            //   488b8424a0000000     | dec                 esp
            //   4889442448           | lea                 eax, dword ptr [0x5ba08]
            //   48837c247000         | dec                 eax
            //   7666                 | mov                 edx, eax
            //   8b442440             | dec                 eax
            //   4889842420010000     | mov                 ecx, dword ptr [esp + 0x90]

        $sequence_8 = { 753a 4883c718 4c39f7 0f8503ffffff 8a9d50020000 488b8551020000 488985e0010000 }
            // n = 7, score = 400
            //   753a                 | mov                 ecx, 0x3e8
            //   4883c718             | dec                 eax
            //   4c39f7               | mov                 edi, ecx
            //   0f8503ffffff         | dec                 eax
            //   8a9d50020000         | mov                 esi, eax
            //   488b8551020000       | mov                 ecx, 0x10
            //   488985e0010000       | rep movsb           byte ptr es:[edi], byte ptr [esi]

        $sequence_9 = { e8???????? 88442437 8a442437 34ff a801 7522 488b442438 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   88442437             | lea                 edx, dword ptr [ebx + 0x79e0]
            //   8a442437             | dec                 esp
            //   34ff                 | lea                 eax, dword ptr [ebx + 0x79f0]
            //   a801                 | movdqa              xmm0, xmmword ptr [ebx + 0x79d0]
            //   7522                 | movdqa              xmmword ptr [ebx + 0x88e0], xmm1
            //   488b442438           | movdqa              xmmword ptr [ebx + 0x88f0], xmm0

    condition:
        7 of them and filesize < 4538368
}