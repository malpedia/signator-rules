rule win_himera_loader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.himera_loader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.himera_loader"
        malpedia_rule_date = "20230124"
        malpedia_hash = "2ee0eebba83dce3d019a90519f2f972c0fcf9686"
        malpedia_version = "20230125"
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
        $sequence_0 = { c645e448 c645e541 c645e656 c645e70e c645e801 c645e90e c645ea18 }
            // n = 7, score = 200
            //   c645e448             | mov                 byte ptr [ebp - 0x1c], 0x48
            //   c645e541             | mov                 byte ptr [ebp - 0x1b], 0x41
            //   c645e656             | mov                 byte ptr [ebp - 0x1a], 0x56
            //   c645e70e             | mov                 byte ptr [ebp - 0x19], 0xe
            //   c645e801             | mov                 byte ptr [ebp - 0x18], 1
            //   c645e90e             | mov                 byte ptr [ebp - 0x17], 0xe
            //   c645ea18             | mov                 byte ptr [ebp - 0x16], 0x18

        $sequence_1 = { e8???????? 33d2 88956382ffff 8d8d6382ffff e8???????? 8bc8 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   33d2                 | xor                 edx, edx
            //   88956382ffff         | mov                 byte ptr [ebp - 0x7d9d], dl
            //   8d8d6382ffff         | lea                 ecx, [ebp - 0x7d9d]
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax

        $sequence_2 = { 837dfc4f 730b 8b4df8 034dfc c60100 ebe6 }
            // n = 6, score = 200
            //   837dfc4f             | cmp                 dword ptr [ebp - 4], 0x4f
            //   730b                 | jae                 0xd
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   034dfc               | add                 ecx, dword ptr [ebp - 4]
            //   c60100               | mov                 byte ptr [ecx], 0
            //   ebe6                 | jmp                 0xffffffe8

        $sequence_3 = { 83c101 894dfc 837dfc0f 7316 }
            // n = 4, score = 200
            //   83c101               | add                 ecx, 1
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   837dfc0f             | cmp                 dword ptr [ebp - 4], 0xf
            //   7316                 | jae                 0x18

        $sequence_4 = { 7c1f 3934bd00a14200 7531 e8???????? 8904bd00a14200 85c0 7514 }
            // n = 7, score = 200
            //   7c1f                 | jl                  0x21
            //   3934bd00a14200       | cmp                 dword ptr [edi*4 + 0x42a100], esi
            //   7531                 | jne                 0x33
            //   e8????????           |                     
            //   8904bd00a14200       | mov                 dword ptr [edi*4 + 0x42a100], eax
            //   85c0                 | test                eax, eax
            //   7514                 | jne                 0x16

        $sequence_5 = { 0f8483000000 eb7d 8b1c9db8fe4100 6800080000 }
            // n = 4, score = 200
            //   0f8483000000         | je                  0x89
            //   eb7d                 | jmp                 0x7f
            //   8b1c9db8fe4100       | mov                 ebx, dword ptr [ebx*4 + 0x41feb8]
            //   6800080000           | push                0x800

        $sequence_6 = { 8945f0 50 8d45f4 64a300000000 894da4 c745a048000000 c645a846 }
            // n = 7, score = 200
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   50                   | push                eax
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   894da4               | mov                 dword ptr [ebp - 0x5c], ecx
            //   c745a048000000       | mov                 dword ptr [ebp - 0x60], 0x48
            //   c645a846             | mov                 byte ptr [ebp - 0x58], 0x46

        $sequence_7 = { 33c9 888d6d82ffff 8d8d6d82ffff e8???????? 8bc8 }
            // n = 5, score = 200
            //   33c9                 | xor                 ecx, ecx
            //   888d6d82ffff         | mov                 byte ptr [ebp - 0x7d93], cl
            //   8d8d6d82ffff         | lea                 ecx, [ebp - 0x7d93]
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax

        $sequence_8 = { 83c404 3db5765718 750e 8b45e8 }
            // n = 4, score = 200
            //   83c404               | add                 esp, 4
            //   3db5765718           | cmp                 eax, 0x185776b5
            //   750e                 | jne                 0x10
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]

        $sequence_9 = { 83c408 89853482ffff 8d95e082ffff 52 6848750000 8d85e482ffff 50 }
            // n = 7, score = 200
            //   83c408               | add                 esp, 8
            //   89853482ffff         | mov                 dword ptr [ebp - 0x7dcc], eax
            //   8d95e082ffff         | lea                 edx, [ebp - 0x7d20]
            //   52                   | push                edx
            //   6848750000           | push                0x7548
            //   8d85e482ffff         | lea                 eax, [ebp - 0x7d1c]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 385024
}