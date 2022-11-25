rule win_logpos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.logpos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.logpos"
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
        $sequence_0 = { c1e810 89c7 85ff 745b b800000100 }
            // n = 5, score = 100
            //   c1e810               | shr                 eax, 0x10
            //   89c7                 | mov                 edi, eax
            //   85ff                 | test                edi, edi
            //   745b                 | je                  0x5d
            //   b800000100           | mov                 eax, 0x10000

        $sequence_1 = { a1???????? 8b5508 8910 6a20 8b450c }
            // n = 5, score = 100
            //   a1????????           |                     
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8910                 | mov                 dword ptr [eax], edx
            //   6a20                 | push                0x20
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_2 = { 48 8d7db0 48 c7c100000100 e8???????? 48 8945e8 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   8d7db0               | lea                 edi, [ebp - 0x50]
            //   48                   | dec                 eax
            //   c7c100000100         | mov                 ecx, 0x10000
            //   e8????????           |                     
            //   48                   | dec                 eax
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax

        $sequence_3 = { 50 8b4208 8b520c 52 50 6a50 e8???????? }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8b4208               | mov                 eax, dword ptr [edx + 8]
            //   8b520c               | mov                 edx, dword ptr [edx + 0xc]
            //   52                   | push                edx
            //   50                   | push                eax
            //   6a50                 | push                0x50
            //   e8????????           |                     

        $sequence_4 = { ac 85c0 7503 41 ebf8 894c241c }
            // n = 6, score = 100
            //   ac                   | lodsb               al, byte ptr [esi]
            //   85c0                 | test                eax, eax
            //   7503                 | jne                 5
            //   41                   | inc                 ecx
            //   ebf8                 | jmp                 0xfffffffa
            //   894c241c             | mov                 dword ptr [esp + 0x1c], ecx

        $sequence_5 = { 48 29c2 48 8955f0 48 }
            // n = 5, score = 100
            //   48                   | dec                 eax
            //   29c2                 | sub                 edx, eax
            //   48                   | dec                 eax
            //   8955f0               | mov                 dword ptr [ebp - 0x10], edx
            //   48                   | dec                 eax

        $sequence_6 = { 83f82f 0f8549000000 8b45fc c680a360400000 8b45fc }
            // n = 5, score = 100
            //   83f82f               | cmp                 eax, 0x2f
            //   0f8549000000         | jne                 0x4f
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   c680a360400000       | mov                 byte ptr [eax + 0x4060a3], 0
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_7 = { c3 55 89e5 83ec04 c745fc00000000 eb33 }
            // n = 6, score = 100
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   83ec04               | sub                 esp, 4
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   eb33                 | jmp                 0x35

        $sequence_8 = { 4d 89dc 48 0fb610 80fa2e 740b 41 }
            // n = 7, score = 100
            //   4d                   | dec                 ebp
            //   89dc                 | mov                 esp, ebx
            //   48                   | dec                 eax
            //   0fb610               | movzx               edx, byte ptr [eax]
            //   80fa2e               | cmp                 dl, 0x2e
            //   740b                 | je                  0xd
            //   41                   | inc                 ecx

        $sequence_9 = { 48 83c450 48 85c0 7522 }
            // n = 5, score = 100
            //   48                   | dec                 eax
            //   83c450               | add                 esp, 0x50
            //   48                   | dec                 eax
            //   85c0                 | test                eax, eax
            //   7522                 | jne                 0x24

    condition:
        7 of them and filesize < 57344
}