rule win_oatboat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.oatboat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.oatboat"
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
        $sequence_0 = { c745e04e744672 c745e465655669 c745e872747561 c745ec6c4d656d c745f06f727900 e8???????? }
            // n = 6, score = 100
            //   c745e04e744672       | jb                  0xffffffbd
            //   c745e465655669       | mov                 edx, dword ptr [ebx + 0x24]
            //   c745e872747561       | inc                 ebx
            //   c745ec6c4d656d       | lea                 eax, [esi + esi]
            //   c745f06f727900       | mov                 ecx, dword ptr [ebx + 0x1c]
            //   e8????????           |                     

        $sequence_1 = { 488bf9 c745e04b004500 33db c745e452004e00 488d4de0 66895df8 c745e845004c00 }
            // n = 7, score = 100
            //   488bf9               | add                 esp, 0x30
            //   c745e04b004500       | push                ebx
            //   33db                 | inc                 ecx
            //   c745e452004e00       | push                esp
            //   488d4de0             | inc                 ecx
            //   66895df8             | push                esi
            //   c745e845004c00       | inc                 ecx

        $sequence_2 = { c745e46f70794d c745e8656d6f72 66c745ec7900 e8???????? 4d8bc4 }
            // n = 5, score = 100
            //   c745e46f70794d       | inc                 ecx
            //   c745e8656d6f72       | push                esi
            //   66c745ec7900         | inc                 ecx
            //   e8????????           |                     
            //   4d8bc4               | push                edi

        $sequence_3 = { e8???????? 488bcf ffd0 488b5c2450 488b742458 488b7c2460 4883c430 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488bcf               | movsx               edx, byte ptr [ebx]
            //   ffd0                 | inc                 ebp
            //   488b5c2450           | movsx               eax, byte ptr [esi + ebx]
            //   488b742458           | lea                 ecx, [edx - 0x41]
            //   488b7c2460           | inc                 ecx
            //   4883c430             | push                edi

        $sequence_4 = { c740e86c000000 e8???????? 4885c0 740e 488bd7 488bc8 e8???????? }
            // n = 7, score = 100
            //   c740e86c000000       | je                  0x92
            //   e8????????           |                     
            //   4885c0               | dec                 ecx
            //   740e                 | mov                 ebx, dword ptr [edx + 0x60]
            //   488bd7               | dec                 eax
            //   488bc8               | cmp                 eax, edi
            //   e8????????           |                     

        $sequence_5 = { 4883653000 488d4de0 4c896538 c745e04e74416c c745e46c6f6361 c745e874655669 c745ec72747561 }
            // n = 7, score = 100
            //   4883653000           | mov                 dword ptr [esp + 0x20], 0x1000
            //   488d4de0             | dec                 eax
            //   4c896538             | lea                 edx, [ebp + 0x30]
            //   c745e04e74416c       | jb                  0xffffffbd
            //   c745e46c6f6361       | mov                 edx, dword ptr [ebx + 0x24]
            //   c745e874655669       | inc                 ebx
            //   c745ec72747561       | lea                 eax, [esi + esi]

        $sequence_6 = { c745f46f727900 e8???????? 4c8d4d38 c744242840000000 4533c0 }
            // n = 5, score = 100
            //   c745f46f727900       | mov                 ecx, edi
            //   e8????????           |                     
            //   4c8d4d38             | call                eax
            //   c744242840000000     | dec                 eax
            //   4533c0               | mov                 ebx, dword ptr [esp + 0x50]

        $sequence_7 = { 0f84a3000000 4d8b5210 4d85d2 0f8496000000 4d397a30 0f848c000000 498b5a60 }
            // n = 7, score = 100
            //   0f84a3000000         | lea                 ecx, [ebp - 0x20]
            //   4d8b5210             | mov                 word ptr [ebp - 8], bx
            //   4d85d2               | mov                 dword ptr [ebp - 0x18], 0x4c0045
            //   0f8496000000         | mov                 word ptr [ebp - 8], bx
            //   4d397a30             | mov                 dword ptr [ebp - 0x18], 0x4c0045
            //   0f848c000000         | mov                 dword ptr [ebp - 0x14], 0x320033
            //   498b5a60             | mov                 dword ptr [ebp - 0x10], 0x44002e

    condition:
        7 of them and filesize < 58368
}