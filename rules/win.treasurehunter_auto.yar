rule win_treasurehunter_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.treasurehunter."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.treasurehunter"
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
        $sequence_0 = { 56 53 8945fc ff15???????? 85c0 }
            // n = 5, score = 300
            //   56                   | push                esi
            //   53                   | push                ebx
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_1 = { 83c40c be???????? ff36 57 }
            // n = 4, score = 300
            //   83c40c               | add                 esp, 0xc
            //   be????????           |                     
            //   ff36                 | push                dword ptr [esi]
            //   57                   | push                edi

        $sequence_2 = { 50 8903 ff15???????? 8b4dfc }
            // n = 4, score = 300
            //   50                   | push                eax
            //   8903                 | mov                 dword ptr [ebx], eax
            //   ff15????????         |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_3 = { ff15???????? 8b4dfc 57 8901 }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   57                   | push                edi
            //   8901                 | mov                 dword ptr [ecx], eax

        $sequence_4 = { 53 56 8b35???????? 8bd9 8b4d08 57 8955fc }
            // n = 7, score = 300
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8b35????????         |                     
            //   8bd9                 | mov                 ebx, ecx
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   57                   | push                edi
            //   8955fc               | mov                 dword ptr [ebp - 4], edx

        $sequence_5 = { 57 8901 e8???????? 56 }
            // n = 4, score = 300
            //   57                   | push                edi
            //   8901                 | mov                 dword ptr [ecx], eax
            //   e8????????           |                     
            //   56                   | push                esi

        $sequence_6 = { 8bf1 85d2 7e0b 4a e8???????? 0fafc6 5e }
            // n = 7, score = 300
            //   8bf1                 | mov                 esi, ecx
            //   85d2                 | test                edx, edx
            //   7e0b                 | jle                 0xd
            //   4a                   | dec                 edx
            //   e8????????           |                     
            //   0fafc6               | imul                eax, esi
            //   5e                   | pop                 esi

        $sequence_7 = { 8bf9 8bca e8???????? 8b7508 }
            // n = 4, score = 300
            //   8bf9                 | mov                 edi, ecx
            //   8bca                 | mov                 ecx, edx
            //   e8????????           |                     
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]

    condition:
        7 of them and filesize < 229376
}