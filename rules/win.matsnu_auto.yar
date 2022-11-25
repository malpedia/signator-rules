rule win_matsnu_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.matsnu."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.matsnu"
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
        $sequence_0 = { 8b7604 0375de 3975ba 0f8229010000 }
            // n = 4, score = 700
            //   8b7604               | mov                 esi, dword ptr [esi + 4]
            //   0375de               | add                 esi, dword ptr [ebp - 0x22]
            //   3975ba               | cmp                 dword ptr [ebp - 0x46], esi
            //   0f8229010000         | jb                  0x12f

        $sequence_1 = { 217506 8b4704 8945fc 8b45fc c9 c20400 }
            // n = 6, score = 700
            //   217506               | and                 dword ptr [ebp + 6], esi
            //   8b4704               | mov                 eax, dword ptr [edi + 4]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   c9                   | leave               
            //   c20400               | ret                 4

        $sequence_2 = { c745dc00000000 c745e000000000 c745e400000000 c745e800000000 c745ec00000000 c645f000 c645f100 }
            // n = 7, score = 700
            //   c745dc00000000       | mov                 dword ptr [ebp - 0x24], 0
            //   c745e000000000       | mov                 dword ptr [ebp - 0x20], 0
            //   c745e400000000       | mov                 dword ptr [ebp - 0x1c], 0
            //   c745e800000000       | mov                 dword ptr [ebp - 0x18], 0
            //   c745ec00000000       | mov                 dword ptr [ebp - 0x14], 0
            //   c645f000             | mov                 byte ptr [ebp - 0x10], 0
            //   c645f100             | mov                 byte ptr [ebp - 0xf], 0

        $sequence_3 = { ff75ba ff7510 e8???????? 8945f6 }
            // n = 4, score = 700
            //   ff75ba               | push                dword ptr [ebp - 0x46]
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   e8????????           |                     
            //   8945f6               | mov                 dword ptr [ebp - 0xa], eax

        $sequence_4 = { 8b7604 3975ea 7327 8b45e6 }
            // n = 4, score = 700
            //   8b7604               | mov                 esi, dword ptr [esi + 4]
            //   3975ea               | cmp                 dword ptr [ebp - 0x16], esi
            //   7327                 | jae                 0x29
            //   8b45e6               | mov                 eax, dword ptr [ebp - 0x1a]

        $sequence_5 = { c785e6fbffff25303458 c785eafbffff2d253258 c785eefbffff7d2e646c c685f2fbffff6c c685f3fbffff00 c745f400000000 }
            // n = 6, score = 700
            //   c785e6fbffff25303458     | mov    dword ptr [ebp - 0x41a], 0x58343025
            //   c785eafbffff2d253258     | mov    dword ptr [ebp - 0x416], 0x5832252d
            //   c785eefbffff7d2e646c     | mov    dword ptr [ebp - 0x412], 0x6c642e7d
            //   c685f2fbffff6c       | mov                 byte ptr [ebp - 0x40e], 0x6c
            //   c685f3fbffff00       | mov                 byte ptr [ebp - 0x40d], 0
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0

        $sequence_6 = { 8b7d08 8b4704 3b45ba 751d ff75ba ff7510 e8???????? }
            // n = 7, score = 700
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8b4704               | mov                 eax, dword ptr [edi + 4]
            //   3b45ba               | cmp                 eax, dword ptr [ebp - 0x46]
            //   751d                 | jne                 0x1f
            //   ff75ba               | push                dword ptr [ebp - 0x46]
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   e8????????           |                     

        $sequence_7 = { c745b400000000 c645b800 c645b900 c745ba00000000 c745be0c000000 }
            // n = 5, score = 700
            //   c745b400000000       | mov                 dword ptr [ebp - 0x4c], 0
            //   c645b800             | mov                 byte ptr [ebp - 0x48], 0
            //   c645b900             | mov                 byte ptr [ebp - 0x47], 0
            //   c745ba00000000       | mov                 dword ptr [ebp - 0x46], 0
            //   c745be0c000000       | mov                 dword ptr [ebp - 0x42], 0xc

        $sequence_8 = { 8a02 884701 837d1002 7223 31c0 }
            // n = 5, score = 700
            //   8a02                 | mov                 al, byte ptr [edx]
            //   884701               | mov                 byte ptr [edi + 1], al
            //   837d1002             | cmp                 dword ptr [ebp + 0x10], 2
            //   7223                 | jb                  0x25
            //   31c0                 | xor                 eax, eax

        $sequence_9 = { 80e1c0 c0e906 08c8 8d55bc }
            // n = 4, score = 700
            //   80e1c0               | and                 cl, 0xc0
            //   c0e906               | shr                 cl, 6
            //   08c8                 | or                  al, cl
            //   8d55bc               | lea                 edx, [ebp - 0x44]

    condition:
        7 of them and filesize < 606992
}