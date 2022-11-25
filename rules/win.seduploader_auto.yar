rule win_seduploader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.seduploader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.seduploader"
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
        $sequence_0 = { 8b4510 83c6fe 8930 8d4601 50 }
            // n = 5, score = 2400
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   83c6fe               | add                 esi, -2
            //   8930                 | mov                 dword ptr [eax], esi
            //   8d4601               | lea                 eax, [esi + 1]
            //   50                   | push                eax

        $sequence_1 = { e8???????? 8b4510 83c6fe 8930 8d4601 50 }
            // n = 6, score = 2400
            //   e8????????           |                     
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   83c6fe               | add                 esi, -2
            //   8930                 | mov                 dword ptr [eax], esi
            //   8d4601               | lea                 eax, [esi + 1]
            //   50                   | push                eax

        $sequence_2 = { 8b4510 83c6fe 8930 8d4601 50 e8???????? }
            // n = 6, score = 2400
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   83c6fe               | add                 esi, -2
            //   8930                 | mov                 dword ptr [eax], esi
            //   8d4601               | lea                 eax, [esi + 1]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_3 = { 5e c3 55 8bec e8???????? 8b4d0c }
            // n = 6, score = 2400
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   e8????????           |                     
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]

        $sequence_4 = { c3 56 6a3e 8bf1 }
            // n = 4, score = 2400
            //   c3                   | ret                 
            //   56                   | push                esi
            //   6a3e                 | push                0x3e
            //   8bf1                 | mov                 esi, ecx

        $sequence_5 = { e8???????? 8b4510 83c6fe 8930 }
            // n = 4, score = 2400
            //   e8????????           |                     
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   83c6fe               | add                 esi, -2
            //   8930                 | mov                 dword ptr [eax], esi

        $sequence_6 = { 56 6a3e 8bf1 e8???????? }
            // n = 4, score = 2400
            //   56                   | push                esi
            //   6a3e                 | push                0x3e
            //   8bf1                 | mov                 esi, ecx
            //   e8????????           |                     

        $sequence_7 = { 50 e8???????? 8b4510 83c6fe 8930 8d4601 50 }
            // n = 7, score = 2400
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   83c6fe               | add                 esi, -2
            //   8930                 | mov                 dword ptr [eax], esi
            //   8d4601               | lea                 eax, [esi + 1]
            //   50                   | push                eax

        $sequence_8 = { 89b5f0feffff 89b5f4feffff e8???????? 83c40c }
            // n = 4, score = 2400
            //   89b5f0feffff         | mov                 dword ptr [ebp - 0x110], esi
            //   89b5f4feffff         | mov                 dword ptr [ebp - 0x10c], esi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_9 = { 89b5ecfeffff 89b5f0feffff 89b5f4feffff e8???????? 83c40c }
            // n = 5, score = 2400
            //   89b5ecfeffff         | mov                 dword ptr [ebp - 0x114], esi
            //   89b5f0feffff         | mov                 dword ptr [ebp - 0x110], esi
            //   89b5f4feffff         | mov                 dword ptr [ebp - 0x10c], esi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

    condition:
        7 of them and filesize < 401408
}