rule win_ismagent_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-29"
        version = "1"
        description = "Detects win.ismagent."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ismagent"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
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
        $sequence_0 = { 803823 740a 46 803c3e00 8d043e }
            // n = 5, score = 200
            //   803823               | cmp                 byte ptr [eax], 0x23
            //   740a                 | je                  0xc
            //   46                   | inc                 esi
            //   803c3e00             | cmp                 byte ptr [esi + edi], 0
            //   8d043e               | lea                 eax, [esi + edi]

        $sequence_1 = { 33ff 8945dc 8b1c9d48404200 895de0 }
            // n = 4, score = 200
            //   33ff                 | xor                 edi, edi
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   8b1c9d48404200       | mov                 ebx, dword ptr [ebx*4 + 0x424048]
            //   895de0               | mov                 dword ptr [ebp - 0x20], ebx

        $sequence_2 = { 83c41c c744243c01000000 57 e8???????? 83c404 8b4c2418 }
            // n = 6, score = 200
            //   83c41c               | add                 esp, 0x1c
            //   c744243c01000000     | mov                 dword ptr [esp + 0x3c], 1
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]

        $sequence_3 = { ffd0 68???????? ff75fc 8bf0 ff15???????? 807d0800 }
            // n = 6, score = 200
            //   ffd0                 | call                eax
            //   68????????           |                     
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     
            //   807d0800             | cmp                 byte ptr [ebp + 8], 0

        $sequence_4 = { 40 46 89442410 47 894c2414 3b4c2428 }
            // n = 6, score = 200
            //   40                   | inc                 eax
            //   46                   | inc                 esi
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   47                   | inc                 edi
            //   894c2414             | mov                 dword ptr [esp + 0x14], ecx
            //   3b4c2428             | cmp                 ecx, dword ptr [esp + 0x28]

        $sequence_5 = { 75f9 8dbc2428650000 2bd6 4f 0f1f8000000000 8a4701 47 }
            // n = 7, score = 200
            //   75f9                 | jne                 0xfffffffb
            //   8dbc2428650000       | lea                 edi, [esp + 0x6528]
            //   2bd6                 | sub                 edx, esi
            //   4f                   | dec                 edi
            //   0f1f8000000000       | nop                 dword ptr [eax]
            //   8a4701               | mov                 al, byte ptr [edi + 1]
            //   47                   | inc                 edi

        $sequence_6 = { 8b3c8d4cc54100 85ff 755d 33c0 89859cf6ffff 89855cfcffff }
            // n = 6, score = 200
            //   8b3c8d4cc54100       | mov                 edi, dword ptr [ecx*4 + 0x41c54c]
            //   85ff                 | test                edi, edi
            //   755d                 | jne                 0x5f
            //   33c0                 | xor                 eax, eax
            //   89859cf6ffff         | mov                 dword ptr [ebp - 0x964], eax
            //   89855cfcffff         | mov                 dword ptr [ebp - 0x3a4], eax

        $sequence_7 = { ff74241c 50 e8???????? 8b7c241c 83c40c }
            // n = 5, score = 200
            //   ff74241c             | push                dword ptr [esp + 0x1c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b7c241c             | mov                 edi, dword ptr [esp + 0x1c]
            //   83c40c               | add                 esp, 0xc

    condition:
        7 of them and filesize < 327680
}