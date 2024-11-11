rule win_blacksuit_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.blacksuit."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blacksuit"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
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
        $sequence_0 = { ff742414 e8???????? 8b6c241c 83c404 }
            // n = 4, score = 200
            //   ff742414             | push                dword ptr [esp + 0x14]
            //   e8????????           |                     
            //   8b6c241c             | mov                 ebp, dword ptr [esp + 0x1c]
            //   83c404               | add                 esp, 4

        $sequence_1 = { 03dd 13c0 03cb 13d0 }
            // n = 4, score = 200
            //   03dd                 | add                 ebx, ebp
            //   13c0                 | adc                 eax, eax
            //   03cb                 | add                 ecx, ebx
            //   13d0                 | adc                 edx, eax

        $sequence_2 = { 8bf2 f7e5 8bf8 8bea }
            // n = 4, score = 200
            //   8bf2                 | mov                 esi, edx
            //   f7e5                 | mul                 ebp
            //   8bf8                 | mov                 edi, eax
            //   8bea                 | mov                 ebp, edx

        $sequence_3 = { 7416 ff7704 e8???????? 83c404 }
            // n = 4, score = 200
            //   7416                 | je                  0x18
            //   ff7704               | push                dword ptr [edi + 4]
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_4 = { 8d4aa6 e8???????? 83c408 8d4c241c }
            // n = 4, score = 100
            //   8d4aa6               | lea                 ecx, [edx - 0x5a]
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8d4c241c             | lea                 ecx, [esp + 0x1c]

        $sequence_5 = { 8d4aa5 e8???????? 83c408 8d4c2414 }
            // n = 4, score = 100
            //   8d4aa5               | lea                 ecx, [edx - 0x5b]
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8d4c2414             | lea                 ecx, [esp + 0x14]

        $sequence_6 = { 6a10 53 ff74242c e8???????? }
            // n = 4, score = 100
            //   6a10                 | push                0x10
            //   53                   | push                ebx
            //   ff74242c             | push                dword ptr [esp + 0x2c]
            //   e8????????           |                     

        $sequence_7 = { 6a10 53 e8???????? 83c410 85c0 }
            // n = 5, score = 100
            //   6a10                 | push                0x10
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax

        $sequence_8 = { 6a10 55 0f11442420 8d4c2450 }
            // n = 4, score = 100
            //   6a10                 | push                0x10
            //   55                   | push                ebp
            //   0f11442420           | movups              xmmword ptr [esp + 0x20], xmm0
            //   8d4c2450             | lea                 ecx, [esp + 0x50]

        $sequence_9 = { 6a10 53 8d442418 50 8d7770 56 }
            // n = 6, score = 100
            //   6a10                 | push                0x10
            //   53                   | push                ebx
            //   8d442418             | lea                 eax, [esp + 0x18]
            //   50                   | push                eax
            //   8d7770               | lea                 esi, [edi + 0x70]
            //   56                   | push                esi

        $sequence_10 = { 8d4aa3 8b7c2414 6888250000 6843741588 }
            // n = 4, score = 100
            //   8d4aa3               | lea                 ecx, [edx - 0x5d]
            //   8b7c2414             | mov                 edi, dword ptr [esp + 0x14]
            //   6888250000           | push                0x2588
            //   6843741588           | push                0x88157443

        $sequence_11 = { 8d4aa3 e8???????? 83c408 6a00 }
            // n = 4, score = 100
            //   8d4aa3               | lea                 ecx, [edx - 0x5d]
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   6a00                 | push                0

    condition:
        7 of them and filesize < 4764672
}