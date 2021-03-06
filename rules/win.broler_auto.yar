rule win_broler_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.broler."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.broler"
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
        $sequence_0 = { 99 f7ff 0fbf849656040000 25ff000000 331c8508704100 }
            // n = 5, score = 100
            //   99                   | cdq                 
            //   f7ff                 | idiv                edi
            //   0fbf849656040000     | movsx               eax, word ptr [esi + edx*4 + 0x456]
            //   25ff000000           | and                 eax, 0xff
            //   331c8508704100       | xor                 ebx, dword ptr [eax*4 + 0x417008]

        $sequence_1 = { 50 e8???????? 83c40c 8d8d18feffff 51 c78518feffff44000000 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d8d18feffff         | lea                 ecx, [ebp - 0x1e8]
            //   51                   | push                ecx
            //   c78518feffff44000000     | mov    dword ptr [ebp - 0x1e8], 0x44

        $sequence_2 = { e8???????? 83f8ff 7447 83f832 7f42 50 8d85b0dffcff }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83f8ff               | cmp                 eax, -1
            //   7447                 | je                  0x49
            //   83f832               | cmp                 eax, 0x32
            //   7f42                 | jg                  0x44
            //   50                   | push                eax
            //   8d85b0dffcff         | lea                 eax, [ebp - 0x32050]

        $sequence_3 = { 8bbed0030000 8b5d08 2bf8 8d04fa 8b51fc 8b7dec 899486e8010000 }
            // n = 7, score = 100
            //   8bbed0030000         | mov                 edi, dword ptr [esi + 0x3d0]
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   2bf8                 | sub                 edi, eax
            //   8d04fa               | lea                 eax, [edx + edi*8]
            //   8b51fc               | mov                 edx, dword ptr [ecx - 4]
            //   8b7dec               | mov                 edi, dword ptr [ebp - 0x14]
            //   899486e8010000       | mov                 dword ptr [esi + eax*4 + 0x1e8], edx

        $sequence_4 = { 33ff 3bcf 7564 c743140f000000 897b10 b8???????? 8bf3 }
            // n = 7, score = 100
            //   33ff                 | xor                 edi, edi
            //   3bcf                 | cmp                 ecx, edi
            //   7564                 | jne                 0x66
            //   c743140f000000       | mov                 dword ptr [ebx + 0x14], 0xf
            //   897b10               | mov                 dword ptr [ebx + 0x10], edi
            //   b8????????           |                     
            //   8bf3                 | mov                 esi, ebx

        $sequence_5 = { 8bc7 c1f808 25ff000000 3298085a4100 8b450c 885802 }
            // n = 6, score = 100
            //   8bc7                 | mov                 eax, edi
            //   c1f808               | sar                 eax, 8
            //   25ff000000           | and                 eax, 0xff
            //   3298085a4100         | xor                 bl, byte ptr [eax + 0x415a08]
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   885802               | mov                 byte ptr [eax + 2], bl

        $sequence_6 = { 898ed4030000 8b5004 8996d8030000 8b4808 }
            // n = 4, score = 100
            //   898ed4030000         | mov                 dword ptr [esi + 0x3d4], ecx
            //   8b5004               | mov                 edx, dword ptr [eax + 4]
            //   8996d8030000         | mov                 dword ptr [esi + 0x3d8], edx
            //   8b4808               | mov                 ecx, dword ptr [eax + 8]

        $sequence_7 = { 837e1410 731e 8b4610 40 }
            // n = 4, score = 100
            //   837e1410             | cmp                 dword ptr [esi + 0x14], 0x10
            //   731e                 | jae                 0x20
            //   8b4610               | mov                 eax, dword ptr [esi + 0x10]
            //   40                   | inc                 eax

        $sequence_8 = { c1f818 81e3ff000000 25ff000000 8b0485085c4100 33049d08644100 8bd9 }
            // n = 6, score = 100
            //   c1f818               | sar                 eax, 0x18
            //   81e3ff000000         | and                 ebx, 0xff
            //   25ff000000           | and                 eax, 0xff
            //   8b0485085c4100       | mov                 eax, dword ptr [eax*4 + 0x415c08]
            //   33049d08644100       | xor                 eax, dword ptr [ebx*4 + 0x416408]
            //   8bd9                 | mov                 ebx, ecx

        $sequence_9 = { 51 8d9590feffff 52 e8???????? 6a11 8d45dc }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   8d9590feffff         | lea                 edx, [ebp - 0x170]
            //   52                   | push                edx
            //   e8????????           |                     
            //   6a11                 | push                0x11
            //   8d45dc               | lea                 eax, [ebp - 0x24]

    condition:
        7 of them and filesize < 275456
}