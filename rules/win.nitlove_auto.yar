rule win_nitlove_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.nitlove."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nitlove"
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
        $sequence_0 = { 57 ff75c8 48 5f }
            // n = 4, score = 200
            //   57                   | push                edi
            //   ff75c8               | push                dword ptr [ebp - 0x38]
            //   48                   | dec                 eax
            //   5f                   | pop                 edi

        $sequence_1 = { e8???????? e8???????? 8d45f8 c745fc50000000 50 6819010200 33db }
            // n = 7, score = 200
            //   e8????????           |                     
            //   e8????????           |                     
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   c745fc50000000       | mov                 dword ptr [ebp - 4], 0x50
            //   50                   | push                eax
            //   6819010200           | push                0x20119
            //   33db                 | xor                 ebx, ebx

        $sequence_2 = { ffd0 8b4dfc 6a00 8904b1 b9???????? }
            // n = 5, score = 200
            //   ffd0                 | call                eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   6a00                 | push                0
            //   8904b1               | mov                 dword ptr [ecx + esi*4], eax
            //   b9????????           |                     

        $sequence_3 = { 33db ba3d10a287 53 53 57 }
            // n = 5, score = 200
            //   33db                 | xor                 ebx, ebx
            //   ba3d10a287           | mov                 edx, 0x87a2103d
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   57                   | push                edi

        $sequence_4 = { 750b 40 a3???????? e9???????? 56 }
            // n = 5, score = 200
            //   750b                 | jne                 0xd
            //   40                   | inc                 eax
            //   a3????????           |                     
            //   e9????????           |                     
            //   56                   | push                esi

        $sequence_5 = { 3c09 7707 46 41 }
            // n = 4, score = 200
            //   3c09                 | cmp                 al, 9
            //   7707                 | ja                  9
            //   46                   | inc                 esi
            //   41                   | inc                 ecx

        $sequence_6 = { e8???????? ffd0 ff37 baff9ece17 b9???????? }
            // n = 5, score = 200
            //   e8????????           |                     
            //   ffd0                 | call                eax
            //   ff37                 | push                dword ptr [edi]
            //   baff9ece17           | mov                 edx, 0x17ce9eff
            //   b9????????           |                     

        $sequence_7 = { 6800000040 bb???????? ba4aaf3b94 50 }
            // n = 4, score = 200
            //   6800000040           | push                0x40000000
            //   bb????????           |                     
            //   ba4aaf3b94           | mov                 edx, 0x943baf4a
            //   50                   | push                eax

        $sequence_8 = { 59 66898c450cfeffff 33c9 668994450efeffff baeb9b12fe }
            // n = 5, score = 200
            //   59                   | pop                 ecx
            //   66898c450cfeffff     | mov                 word ptr [ebp + eax*2 - 0x1f4], cx
            //   33c9                 | xor                 ecx, ecx
            //   668994450efeffff     | mov                 word ptr [ebp + eax*2 - 0x1f2], dx
            //   baeb9b12fe           | mov                 edx, 0xfe129beb

        $sequence_9 = { ff750c ff7508 6aff ffd0 }
            // n = 4, score = 200
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   6aff                 | push                -1
            //   ffd0                 | call                eax

    condition:
        7 of them and filesize < 49152
}