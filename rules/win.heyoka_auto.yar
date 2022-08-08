rule win_heyoka_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-08-05"
        version = "1"
        description = "Detects win.heyoka."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.heyoka"
        malpedia_rule_date = "20220805"
        malpedia_hash = "6ec06c64bcfdbeda64eff021c766b4ce34542b71"
        malpedia_version = "20220808"
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
        $sequence_0 = { e8???????? 83c408 e9???????? 8a15???????? 8895e8efffff b900010000 33c0 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   e9????????           |                     
            //   8a15????????         |                     
            //   8895e8efffff         | mov                 byte ptr [ebp - 0x1018], dl
            //   b900010000           | mov                 ecx, 0x100
            //   33c0                 | xor                 eax, eax

        $sequence_1 = { 51 894dfc 8b4508 83e002 85c0 743b 68???????? }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83e002               | and                 eax, 2
            //   85c0                 | test                eax, eax
            //   743b                 | je                  0x3d
            //   68????????           |                     

        $sequence_2 = { 8be5 5d c3 55 8bec 83ec70 c7459000000000 }
            // n = 7, score = 100
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec70               | sub                 esp, 0x70
            //   c7459000000000       | mov                 dword ptr [ebp - 0x70], 0

        $sequence_3 = { 8b8dd8feffff 894de4 8b55e4 833a00 0f8480020000 6804010000 6a00 }
            // n = 7, score = 100
            //   8b8dd8feffff         | mov                 ecx, dword ptr [ebp - 0x128]
            //   894de4               | mov                 dword ptr [ebp - 0x1c], ecx
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]
            //   833a00               | cmp                 dword ptr [edx], 0
            //   0f8480020000         | je                  0x286
            //   6804010000           | push                0x104
            //   6a00                 | push                0

        $sequence_4 = { 84d2 7425 0fb6d2 f68261d7011004 740c ff01 85f6 }
            // n = 7, score = 100
            //   84d2                 | test                dl, dl
            //   7425                 | je                  0x27
            //   0fb6d2               | movzx               edx, dl
            //   f68261d7011004       | test                byte ptr [edx + 0x1001d761], 4
            //   740c                 | je                  0xe
            //   ff01                 | inc                 dword ptr [ecx]
            //   85f6                 | test                esi, esi

        $sequence_5 = { 8b45fc 8b4df0 c784814cde000001000000 8b55fc 8b45f0 8b8c9038e30000 8b55fc }
            // n = 7, score = 100
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   c784814cde000001000000     | mov    dword ptr [ecx + eax*4 + 0xde4c], 1
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8b8c9038e30000       | mov                 ecx, dword ptr [eax + edx*4 + 0xe338]
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]

        $sequence_6 = { c705????????01000000 8b4df8 51 e8???????? 83c404 b801000000 }
            // n = 6, score = 100
            //   c705????????01000000     |     
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   b801000000           | mov                 eax, 1

        $sequence_7 = { 8b4df8 8b9150280100 d1ea 8b45f8 899050280100 8b4df8 }
            // n = 6, score = 100
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   8b9150280100         | mov                 edx, dword ptr [ecx + 0x12850]
            //   d1ea                 | shr                 edx, 1
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   899050280100         | mov                 dword ptr [eax + 0x12850], edx
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]

        $sequence_8 = { 8d45f8 50 6a00 6a00 8d8ddcfeffff 51 8b5508 }
            // n = 7, score = 100
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d8ddcfeffff         | lea                 ecx, [ebp - 0x124]
            //   51                   | push                ecx
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]

        $sequence_9 = { 898580d7feff c78588d7feff00000000 8d8d94d7feff e8???????? c745fc00000000 c78584d7feff00000000 c78590d7feff00000000 }
            // n = 7, score = 100
            //   898580d7feff         | mov                 dword ptr [ebp - 0x12880], eax
            //   c78588d7feff00000000     | mov    dword ptr [ebp - 0x12878], 0
            //   8d8d94d7feff         | lea                 ecx, [ebp - 0x1286c]
            //   e8????????           |                     
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   c78584d7feff00000000     | mov    dword ptr [ebp - 0x1287c], 0
            //   c78590d7feff00000000     | mov    dword ptr [ebp - 0x12870], 0

    condition:
        7 of them and filesize < 270336
}