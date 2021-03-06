rule win_rising_sun_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.rising_sun."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rising_sun"
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
        $sequence_0 = { e8???????? 488d8d30070000 33d2 41b81c080000 e8???????? 488d542420 488d4c2428 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488d8d30070000       | mov                 eax, dword ptr [ebp + 0x28]
            //   33d2                 | dec                 eax
            //   41b81c080000         | lea                 ecx, [ebx + 1]
            //   e8????????           |                     
            //   488d542420           | dec                 eax
            //   488d4c2428           | mov                 dword ptr [eax + edx*8], ecx

        $sequence_1 = { 488d940d20060000 458bc7 488d0da0710100 488b0cc1 488b442460 4c8d4c2448 }
            // n = 6, score = 100
            //   488d940d20060000     | xor                 edi, edi
            //   458bc7               | dec                 esp
            //   488d0da0710100       | mov                 esp, edx
            //   488b0cc1             | dec                 eax
            //   488b442460           | test                ecx, ecx
            //   4c8d4c2448           | je                  0x11c4

        $sequence_2 = { ff15???????? 85c0 7528 448d4801 4c8d05cfc60100 488d4c2468 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   85c0                 | dec                 esp
            //   7528                 | cmp                 ebp, edx
            //   448d4801             | jb                  0x1c09
            //   4c8d05cfc60100       | mov                 ecx, 0x80070057
            //   488d4c2468           | int3                

        $sequence_3 = { 488b5520 488bcd 4803c0 488b14c2 e8???????? 493b5e10 }
            // n = 6, score = 100
            //   488b5520             | dec                 eax
            //   488bcd               | lea                 ecx, [ebx + 0x34]
            //   4803c0               | jmp                 0xdfa
            //   488b14c2             | inc                 ecx
            //   e8????????           |                     
            //   493b5e10             | mov                 ebx, ebp

        $sequence_4 = { 7203 488b00 488bc8 e8???????? 3dc8000000 0f95c3 }
            // n = 6, score = 100
            //   7203                 | dec                 esp
            //   488b00               | lea                 ebp, [0x1031d]
            //   488bc8               | dec                 ecx
            //   e8????????           |                     
            //   3dc8000000           | cmp                 dword ptr [ebp + edi*8], 0
            //   0f95c3               | je                  0x351

        $sequence_5 = { 4883c202 48ffcf 75eb eb14 8bfb 663901 48c7c1ffffffff }
            // n = 7, score = 100
            //   4883c202             | mov                 ebx, dword ptr [esp + 0x30]
            //   48ffcf               | dec                 eax
            //   75eb                 | mov                 esi, dword ptr [esp + 0x38]
            //   eb14                 | dec                 eax
            //   8bfb                 | dec                 eax
            //   663901               | add                 esp, 0x20
            //   48c7c1ffffffff       | inc                 ecx

        $sequence_6 = { 660f1f440000 0fb602 48ffc2 88440aff 84c0 75f2 }
            // n = 6, score = 100
            //   660f1f440000         | mov                 dword ptr [esp + 0x62], eax
            //   0fb602               | inc                 ebp
            //   48ffc2               | xor                 esp, esp
            //   88440aff             | jmp                 0x18b1
            //   84c0                 | inc                 ebp
            //   75f2                 | xor                 esp, esp

        $sequence_7 = { e8???????? 488be8 4885c0 74a9 488b5308 4c8b03 488bc8 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488be8               | dec                 eax
            //   4885c0               | mov                 edx, dword ptr [ecx + 0x10]
            //   74a9                 | dec                 eax
            //   488b5308             | mov                 ebx, ecx
            //   4c8b03               | dec                 eax
            //   488bc8               | inc                 edx

        $sequence_8 = { e8???????? e9???????? 4d85f6 7445 498bde 4c3bf6 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   e9????????           |                     
            //   4d85f6               | cmp                 eax, 3
            //   7445                 | jae                 0xb60
            //   498bde               | mov                 eax, ecx
            //   4c3bf6               | jmp                 0xb6a

        $sequence_9 = { 488d542434 488bcb ff15???????? 488905???????? 4885c0 74c2 488d54243e }
            // n = 7, score = 100
            //   488d542434           | mov                 dword ptr [ebp + 0xf8], 0x52973f09
            //   488bcb               | mov                 dword ptr [ebp + 0xfc], 0x65a7acc6
            //   ff15????????         |                     
            //   488905????????       |                     
            //   4885c0               | mov                 dword ptr [ebp + 0x100], 0xd3ee930f
            //   74c2                 | mov                 word ptr [ebp + 0x104], 0xd35
            //   488d54243e           | mov                 dword ptr [ebp + 0x1f8], 0xf39684dc

    condition:
        7 of them and filesize < 409600
}