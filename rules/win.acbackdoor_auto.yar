rule win_acbackdoor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.acbackdoor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.acbackdoor"
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
        $sequence_0 = { e8???????? 85c0 0f85b7000000 f6432802 0f8549010000 0fb64c242f 8b532c }
            // n = 7, score = 100
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f85b7000000         | jne                 0xbd
            //   f6432802             | test                byte ptr [ebx + 0x28], 2
            //   0f8549010000         | jne                 0x14f
            //   0fb64c242f           | movzx               ecx, byte ptr [esp + 0x2f]
            //   8b532c               | mov                 edx, dword ptr [ebx + 0x2c]

        $sequence_1 = { ff15???????? e9???????? 83ff55 751a c7442408???????? 895c2404 893424 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   e9????????           |                     
            //   83ff55               | cmp                 edi, 0x55
            //   751a                 | jne                 0x1c
            //   c7442408????????     |                     
            //   895c2404             | mov                 dword ptr [esp + 4], ebx
            //   893424               | mov                 dword ptr [esp], esi

        $sequence_2 = { e8???????? 85c0 75e1 f7df 897d00 83c41c 5b }
            // n = 7, score = 100
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   75e1                 | jne                 0xffffffe3
            //   f7df                 | neg                 edi
            //   897d00               | mov                 dword ptr [ebp], edi
            //   83c41c               | add                 esp, 0x1c
            //   5b                   | pop                 ebx

        $sequence_3 = { e8???????? 85c0 741e 8b83180e0000 c70424???????? 89442404 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   741e                 | je                  0x20
            //   8b83180e0000         | mov                 eax, dword ptr [ebx + 0xe18]
            //   c70424????????       |                     
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   e8????????           |                     

        $sequence_4 = { 8b6c2414 8dac15dcbc1b8f 89da 01ee c1c205 89dd 01d6 }
            // n = 7, score = 100
            //   8b6c2414             | mov                 ebp, dword ptr [esp + 0x14]
            //   8dac15dcbc1b8f       | lea                 ebp, [ebp + edx - 0x70e44324]
            //   89da                 | mov                 edx, ebx
            //   01ee                 | add                 esi, ebp
            //   c1c205               | rol                 edx, 5
            //   89dd                 | mov                 ebp, ebx
            //   01d6                 | add                 esi, edx

        $sequence_5 = { e8???????? 8b8670050000 85c0 7403 c60000 8b4624 85c0 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b8670050000         | mov                 eax, dword ptr [esi + 0x570]
            //   85c0                 | test                eax, eax
            //   7403                 | je                  5
            //   c60000               | mov                 byte ptr [eax], 0
            //   8b4624               | mov                 eax, dword ptr [esi + 0x24]
            //   85c0                 | test                eax, eax

        $sequence_6 = { e8???????? 8b4500 895c2404 c74424081c000000 8b481c 890c24 ff5018 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b4500               | mov                 eax, dword ptr [ebp]
            //   895c2404             | mov                 dword ptr [esp + 4], ebx
            //   c74424081c000000     | mov                 dword ptr [esp + 8], 0x1c
            //   8b481c               | mov                 ecx, dword ptr [eax + 0x1c]
            //   890c24               | mov                 dword ptr [esp], ecx
            //   ff5018               | call                dword ptr [eax + 0x18]

        $sequence_7 = { e9???????? 81ff807c0000 751a c7442408???????? 895c2404 893424 ff15???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   81ff807c0000         | cmp                 edi, 0x7c80
            //   751a                 | jne                 0x1c
            //   c7442408????????     |                     
            //   895c2404             | mov                 dword ptr [esp + 4], ebx
            //   893424               | mov                 dword ptr [esp], esi
            //   ff15????????         |                     

        $sequence_8 = { e8???????? 85c0 75db 8b4b0c 8b542424 890a 83c410 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   75db                 | jne                 0xffffffdd
            //   8b4b0c               | mov                 ecx, dword ptr [ebx + 0xc]
            //   8b542424             | mov                 edx, dword ptr [esp + 0x24]
            //   890a                 | mov                 dword ptr [edx], ecx
            //   83c410               | add                 esp, 0x10

        $sequence_9 = { e8???????? 89c7 85c0 7516 8b442464 8b4c2460 89da }
            // n = 7, score = 100
            //   e8????????           |                     
            //   89c7                 | mov                 edi, eax
            //   85c0                 | test                eax, eax
            //   7516                 | jne                 0x18
            //   8b442464             | mov                 eax, dword ptr [esp + 0x64]
            //   8b4c2460             | mov                 ecx, dword ptr [esp + 0x60]
            //   89da                 | mov                 edx, ebx

    condition:
        7 of them and filesize < 1704960
}