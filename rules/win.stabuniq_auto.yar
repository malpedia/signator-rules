rule win_stabuniq_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.stabuniq."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stabuniq"
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
        $sequence_0 = { 8b45ec 50 8b4d10 ff5124 8945bc 8b55ec 52 }
            // n = 7, score = 100
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   50                   | push                eax
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   ff5124               | call                dword ptr [ecx + 0x24]
            //   8945bc               | mov                 dword ptr [ebp - 0x44], eax
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   52                   | push                edx

        $sequence_1 = { 7537 c745fc602b4000 8b4d08 8b55fc 039114020000 8955fc 8b4508 }
            // n = 7, score = 100
            //   7537                 | jne                 0x39
            //   c745fc602b4000       | mov                 dword ptr [ebp - 4], 0x402b60
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   039114020000         | add                 edx, dword ptr [ecx + 0x214]
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_2 = { 746a c745f800000000 8b4d08 8b9110020000 52 8b4508 }
            // n = 6, score = 100
            //   746a                 | je                  0x6c
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b9110020000         | mov                 edx, dword ptr [ecx + 0x210]
            //   52                   | push                edx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_3 = { 50 8b4d10 81c160020000 51 8d95f0feffff 52 8b4510 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   81c160020000         | add                 ecx, 0x260
            //   51                   | push                ecx
            //   8d95f0feffff         | lea                 edx, [ebp - 0x110]
            //   52                   | push                edx
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]

        $sequence_4 = { 8be5 5d c20400 55 8bec 83ec10 6a08 }
            // n = 7, score = 100
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec10               | sub                 esp, 0x10
            //   6a08                 | push                8

        $sequence_5 = { 8b45f0 8b08 51 8b55f4 83ea04 8955f4 8b45f4 }
            // n = 7, score = 100
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   51                   | push                ecx
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   83ea04               | sub                 edx, 4
            //   8955f4               | mov                 dword ptr [ebp - 0xc], edx
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_6 = { 8b4d20 ff9194010000 83f801 0f8593000000 8b5520 52 8b4518 }
            // n = 7, score = 100
            //   8b4d20               | mov                 ecx, dword ptr [ebp + 0x20]
            //   ff9194010000         | call                dword ptr [ecx + 0x194]
            //   83f801               | cmp                 eax, 1
            //   0f8593000000         | jne                 0x99
            //   8b5520               | mov                 edx, dword ptr [ebp + 0x20]
            //   52                   | push                edx
            //   8b4518               | mov                 eax, dword ptr [ebp + 0x18]

        $sequence_7 = { 83c001 894510 8b4dfc 83c101 894dfc 8b55e8 81e2ff000000 }
            // n = 7, score = 100
            //   83c001               | add                 eax, 1
            //   894510               | mov                 dword ptr [ebp + 0x10], eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   83c101               | add                 ecx, 1
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8b55e8               | mov                 edx, dword ptr [ebp - 0x18]
            //   81e2ff000000         | and                 edx, 0xff

        $sequence_8 = { e9???????? 6a00 8d8dccfbffff 51 8b55ec 52 8b45e4 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   6a00                 | push                0
            //   8d8dccfbffff         | lea                 ecx, [ebp - 0x434]
            //   51                   | push                ecx
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   52                   | push                edx
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]

        $sequence_9 = { 8b4d10 ff512c 8b5510 81c237030000 52 8b450c 50 }
            // n = 7, score = 100
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   ff512c               | call                dword ptr [ecx + 0x2c]
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   81c237030000         | add                 edx, 0x337
            //   52                   | push                edx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 57344
}