rule win_tiger_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.tiger_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tiger_rat"
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
        $sequence_0 = { 0100 74ad 0100 b5ad }
            // n = 4, score = 100
            //   0100                 | mov                 word ptr [ecx - 3], dx
            //   74ad                 | mov                 byte ptr [ecx - 1], dl
            //   0100                 | ret                 
            //   b5ad                 | add                 dword ptr [eax], eax

        $sequence_1 = { 0100 6666660f1f840000000000 488951f1 8951f9 668951fd }
            // n = 5, score = 100
            //   0100                 | add                 dword ptr [eax], eax
            //   6666660f1f840000000000     | nop    word ptr [eax + eax]
            //   488951f1             | dec                 eax
            //   8951f9               | mov                 dword ptr [ecx - 0xf], edx
            //   668951fd             | mov                 dword ptr [ecx - 7], edx

        $sequence_2 = { 488bc8 4885c0 0f84af000000 488b00 48897c2440 ff5018 }
            // n = 6, score = 100
            //   488bc8               | add                 dword ptr [eax], eax
            //   4885c0               | mov                 ch, 0xad
            //   0f84af000000         | add                 dword ptr [eax], eax
            //   488b00               | movsb               byte ptr es:[edi], byte ptr [esi]
            //   48897c2440           | lodsd               eax, dword ptr [esi]
            //   ff5018               | add                 dword ptr [eax], eax

        $sequence_3 = { 0100 85ad010070ad 0100 6666660f1f840000000000 }
            // n = 4, score = 100
            //   0100                 | lodsd               eax, dword ptr [esi]
            //   85ad010070ad         | add                 dword ptr [eax], eax
            //   0100                 | xchg                eax, ecx
            //   6666660f1f840000000000     | add    dword ptr [eax], eax

        $sequence_4 = { 0100 7fad 0100 9c }
            // n = 4, score = 100
            //   0100                 | mov                 word ptr [ebp - 0x5288ffff], gs
            //   7fad                 | add                 dword ptr [eax], eax
            //   0100                 | lodsd               eax, dword ptr [esi]
            //   9c                   | add                 dword ptr [eax], eax

        $sequence_5 = { 0100 8cad010077ad 0100 a0????????ad010089 ad 0100 }
            // n = 6, score = 100
            //   0100                 | mov                 word ptr [ebp - 0x5288ffff], gs
            //   8cad010077ad         | add                 dword ptr [eax], eax
            //   0100                 | add                 dword ptr [eax], eax
            //   a0????????ad010089     |     
            //   ad                   | mov                 word ptr [ebp - 0x5288ffff], gs
            //   0100                 | add                 dword ptr [eax], eax

        $sequence_6 = { 0100 7bad 0100 8cad010077ad }
            // n = 4, score = 100
            //   0100                 | add                 dword ptr [eax], eax
            //   7bad                 | lodsd               eax, dword ptr [esi]
            //   0100                 | lodsd               eax, dword ptr [esi]
            //   8cad010077ad         | add                 dword ptr [eax], eax

        $sequence_7 = { a8fb 741a 8b05???????? 2b05???????? 48ffc3 }
            // n = 5, score = 100
            //   a8fb                 | dec                 eax
            //   741a                 | mov                 eax, dword ptr [eax]
            //   8b05????????         |                     
            //   2b05????????         |                     
            //   48ffc3               | dec                 eax

        $sequence_8 = { 0100 91 ad 0100 }
            // n = 4, score = 100
            //   0100                 | add                 dword ptr [eax], eax
            //   91                   | mov                 word ptr [ebp - 0x5288ffff], gs
            //   ad                   | add                 dword ptr [eax], eax
            //   0100                 | lodsd               eax, dword ptr [esi]

        $sequence_9 = { 4533ed 49bcffffffffffffff0f 0f1f4000 418b06 85c0 }
            // n = 5, score = 100
            //   4533ed               | dec                 eax
            //   49bcffffffffffffff0f     | mov    ecx, eax
            //   0f1f4000             | dec                 eax
            //   418b06               | test                eax, eax
            //   85c0                 | je                  0xb5

        $sequence_10 = { ff15???????? 448be8 85c0 0f8470010000 488b442448 488d0dd7230100 4c8d4c2460 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   448be8               | inc                 ebx
            //   85c0                 | je                  0x135
            //   0f8470010000         | dec                 eax
            //   488b442448           | lea                 ebx, dword ptr [esi + eax]
            //   488d0dd7230100       | dec                 eax
            //   4c8d4c2460           | mov                 ecx, ebx

        $sequence_11 = { 83675c00 488d05f9c5ffff 488d4f28 48894710 48894708 }
            // n = 5, score = 100
            //   83675c00             | dec                 ecx
            //   488d05f9c5ffff       | mov                 esp, 0xffffffff
            //   488d4f28             | nop                 dword ptr [eax]
            //   48894710             | inc                 ecx
            //   48894708             | mov                 eax, dword ptr [esi]

        $sequence_12 = { 0f842f010000 488d1c06 488bcb ff15???????? 488be8 }
            // n = 5, score = 100
            //   0f842f010000         | mov                 dword ptr [esp + 0x40], edi
            //   488d1c06             | call                dword ptr [eax + 0x18]
            //   488bcb               | inc                 ebp
            //   ff15????????         |                     
            //   488be8               | xor                 ebp, ebp

        $sequence_13 = { 488bce ff15???????? 4885ff 750e 4885db }
            // n = 5, score = 100
            //   488bce               | test                eax, eax
            //   ff15????????         |                     
            //   4885ff               | test                al, 0xfb
            //   750e                 | je                  0x1e
            //   4885db               | dec                 eax

        $sequence_14 = { e8???????? 4883c8ff 4883c428 c3 4863d1 4c8d05a61c0100 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   4883c8ff             | dec                 eax
            //   4883c428             | mov                 ebp, eax
            //   c3                   | and                 dword ptr [edi + 0x5c], 0
            //   4863d1               | dec                 eax
            //   4c8d05a61c0100       | lea                 eax, dword ptr [0xffffc5f9]

        $sequence_15 = { 0100 9c ad 0100 }
            // n = 4, score = 100
            //   0100                 | xchg                eax, ecx
            //   9c                   | lodsd               eax, dword ptr [esi]
            //   ad                   | add                 dword ptr [eax], eax
            //   0100                 | test                dword ptr [ebp - 0x528fffff], ebp

    condition:
        7 of them and filesize < 557056
}