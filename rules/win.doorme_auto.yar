rule win_doorme_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.doorme."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.doorme"
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
        $sequence_0 = { 4c8d0d4dcb0100 b901000000 4c8d0539cb0100 488d1502870100 e8???????? 8bcb 4885c0 }
            // n = 7, score = 100
            //   4c8d0d4dcb0100       | inc                 ecx
            //   b901000000           | mov                 eax, 0x2000
            //   4c8d0539cb0100       | dec                 eax
            //   488d1502870100       | lea                 edx, [ebp + 0x2e0]
            //   e8????????           |                     
            //   8bcb                 | dec                 ecx
            //   4885c0               | mov                 ecx, edi

        $sequence_1 = { ff15???????? 33db 85c0 0f84cb000000 8b442450 4c8d05dea9ffff }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   33db                 | dec                 eax
            //   85c0                 | mov                 eax, edx
            //   0f84cb000000         | dec                 eax
            //   8b442450             | mov                 ecx, dword ptr [ebp - 0x39]
            //   4c8d05dea9ffff       | dec                 eax

        $sequence_2 = { 49ffc0 42803c0700 75f6 488bd7 488d4d68 e8???????? 90 }
            // n = 7, score = 100
            //   49ffc0               | lea                 eax, [edx + 1]
            //   42803c0700           | inc                 esp
            //   75f6                 | mov                 byte ptr [eax + ecx], al
            //   488bd7               | inc                 ecx
            //   488d4d68             | lea                 eax, [ecx + 3]
            //   e8????????           |                     
            //   90                   | inc                 esp

        $sequence_3 = { 488905???????? ff15???????? 483305???????? 488d15e6be0100 488bcb 488905???????? ff15???????? }
            // n = 7, score = 100
            //   488905????????       |                     
            //   ff15????????         |                     
            //   483305????????       |                     
            //   488d15e6be0100       | jne                 0x1170
            //   488bcb               | movdqu              xmmword ptr [esp + 0x50], xmm0
            //   488905????????       |                     
            //   ff15????????         |                     

        $sequence_4 = { e8???????? 660f6f05???????? f30f7f4588 c644247800 483bd8 480f42c3 498bd6 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   660f6f05????????     |                     
            //   f30f7f4588           | dec                 eax
            //   c644247800           | mov                 ecx, edi
            //   483bd8               | dec                 eax
            //   480f42c3             | inc                 esi
            //   498bd6               | dec                 eax

        $sequence_5 = { 488d4db7 e8???????? 49897d10 49897d18 0f1000 410f114500 0f104810 }
            // n = 7, score = 100
            //   488d4db7             | inc                 esp
            //   e8????????           |                     
            //   49897d10             | lea                 ecx, [ecx + 0x432aff97]
            //   49897d18             | add                 edx, eax
            //   0f1000               | inc                 ecx
            //   410f114500           | lea                 ecx, [edx - 0x546bdc59]
            //   0f104810             | inc                 ecx

        $sequence_6 = { 744f e8???????? e8???????? e8???????? 488d15cac80100 488d0d93c80100 }
            // n = 6, score = 100
            //   744f                 | dec                 eax
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   488d15cac80100       | cmp                 edx, 0x10
            //   488d0d93c80100       | jb                  0xa75

        $sequence_7 = { 7410 488d0dc2390300 fe0c08 803c0800 7f4e 488bcb e8???????? }
            // n = 7, score = 100
            //   7410                 | ja                  0xb8b
            //   488d0dc2390300       | dec                 ecx
            //   fe0c08               | mov                 ecx, eax
            //   803c0800             | dec                 eax
            //   7f4e                 | add                 ebx, 0x10
            //   488bcb               | dec                 eax
            //   e8????????           |                     

        $sequence_8 = { 4032742402 4132d4 321424 4132f4 40323424 4132d0 }
            // n = 6, score = 100
            //   4032742402           | test                ebx, ebx
            //   4132d4               | jns                 0x18ad
            //   321424               | dec                 ecx
            //   4132f4               | mov                 eax, dword ptr [esp]
            //   40323424             | mov                 edx, ebx
            //   4132d0               | dec                 ecx

        $sequence_9 = { 488b4b28 e8???????? 488d058a5f0200 488903 40f6c701 740d ba30000000 }
            // n = 7, score = 100
            //   488b4b28             | mov                 ecx, 0x10
            //   e8????????           |                     
            //   488d058a5f0200       | nop                 dword ptr [eax]
            //   488903               | movzx               eax, byte ptr [edx - 2]
            //   40f6c701             | mov                 byte ptr [ecx - 1], al
            //   740d                 | movzx               eax, byte ptr [edx - 1]
            //   ba30000000           | mov                 byte ptr [ecx], al

    condition:
        7 of them and filesize < 580608
}