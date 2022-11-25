rule win_monero_miner_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.monero_miner."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.monero_miner"
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
        $sequence_0 = { c7042402020000 89442404 ff15???????? 83ec08 85c0 ba02000000 7409 }
            // n = 7, score = 100
            //   c7042402020000       | mov                 dword ptr [esp], 0x202
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   ff15????????         |                     
            //   83ec08               | sub                 esp, 8
            //   85c0                 | test                eax, eax
            //   ba02000000           | mov                 edx, 2
            //   7409                 | je                  0xb

        $sequence_1 = { 56 53 83e4f0 83ec50 8b4508 8b18 85db }
            // n = 7, score = 100
            //   56                   | push                esi
            //   53                   | push                ebx
            //   83e4f0               | and                 esp, 0xfffffff0
            //   83ec50               | sub                 esp, 0x50
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b18                 | mov                 ebx, dword ptr [eax]
            //   85db                 | test                ebx, ebx

        $sequence_2 = { 8b9424fc020000 896c2458 01c1 89c5 11d3 0fa4d016 0fa4ea16 }
            // n = 7, score = 100
            //   8b9424fc020000       | mov                 edx, dword ptr [esp + 0x2fc]
            //   896c2458             | mov                 dword ptr [esp + 0x58], ebp
            //   01c1                 | add                 ecx, eax
            //   89c5                 | mov                 ebp, eax
            //   11d3                 | adc                 ebx, edx
            //   0fa4d016             | shld                eax, edx, 0x16
            //   0fa4ea16             | shld                edx, ebp, 0x16

        $sequence_3 = { 8b7c2420 83c701 83d200 897c2418 39d3 8954241c 0f82e8020000 }
            // n = 7, score = 100
            //   8b7c2420             | mov                 edi, dword ptr [esp + 0x20]
            //   83c701               | add                 edi, 1
            //   83d200               | adc                 edx, 0
            //   897c2418             | mov                 dword ptr [esp + 0x18], edi
            //   39d3                 | cmp                 ebx, edx
            //   8954241c             | mov                 dword ptr [esp + 0x1c], edx
            //   0f82e8020000         | jb                  0x2ee

        $sequence_4 = { c7442404???????? 83c602 89442408 e8???????? 0fb613 893424 83c301 }
            // n = 7, score = 100
            //   c7442404????????     |                     
            //   83c602               | add                 esi, 2
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   e8????????           |                     
            //   0fb613               | movzx               edx, byte ptr [ebx]
            //   893424               | mov                 dword ptr [esp], esi
            //   83c301               | add                 ebx, 1

        $sequence_5 = { 8d442454 89442404 8b4308 890424 e8???????? 85c0 89c7 }
            // n = 7, score = 100
            //   8d442454             | lea                 eax, [esp + 0x54]
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   8b4308               | mov                 eax, dword ptr [ebx + 8]
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   89c7                 | mov                 edi, eax

        $sequence_6 = { 8b842498000000 31ee 8994248c000000 89da 89b42480000000 8bb424a0000000 31fa }
            // n = 7, score = 100
            //   8b842498000000       | mov                 eax, dword ptr [esp + 0x98]
            //   31ee                 | xor                 esi, ebp
            //   8994248c000000       | mov                 dword ptr [esp + 0x8c], edx
            //   89da                 | mov                 edx, ebx
            //   89b42480000000       | mov                 dword ptr [esp + 0x80], esi
            //   8bb424a0000000       | mov                 esi, dword ptr [esp + 0xa0]
            //   31fa                 | xor                 edx, edi

        $sequence_7 = { 89f5 31c5 31fa 8b8424c0020000 899424d4020000 8b9424c4020000 89ac24d0020000 }
            // n = 7, score = 100
            //   89f5                 | mov                 ebp, esi
            //   31c5                 | xor                 ebp, eax
            //   31fa                 | xor                 edx, edi
            //   8b8424c0020000       | mov                 eax, dword ptr [esp + 0x2c0]
            //   899424d4020000       | mov                 dword ptr [esp + 0x2d4], edx
            //   8b9424c4020000       | mov                 edx, dword ptr [esp + 0x2c4]
            //   89ac24d0020000       | mov                 dword ptr [esp + 0x2d0], ebp

        $sequence_8 = { c7820c01000004000000 c7821c01000020000000 0f847bfbffff 807c244300 c782fc00000000010000 c7820c01000004000000 }
            // n = 6, score = 100
            //   c7820c01000004000000     | mov    dword ptr [edx + 0x10c], 4
            //   c7821c01000020000000     | mov    dword ptr [edx + 0x11c], 0x20
            //   0f847bfbffff         | je                  0xfffffb81
            //   807c244300           | cmp                 byte ptr [esp + 0x43], 0
            //   c782fc00000000010000     | mov    dword ptr [edx + 0xfc], 0x100
            //   c7820c01000004000000     | mov    dword ptr [edx + 0x10c], 4

        $sequence_9 = { c6040401 8b4324 85c0 7821 0fb6cc 0fb6f0 c6043401 }
            // n = 7, score = 100
            //   c6040401             | mov                 byte ptr [esp + eax], 1
            //   8b4324               | mov                 eax, dword ptr [ebx + 0x24]
            //   85c0                 | test                eax, eax
            //   7821                 | js                  0x23
            //   0fb6cc               | movzx               ecx, ah
            //   0fb6f0               | movzx               esi, al
            //   c6043401             | mov                 byte ptr [esp + esi], 1

    condition:
        7 of them and filesize < 1425408
}