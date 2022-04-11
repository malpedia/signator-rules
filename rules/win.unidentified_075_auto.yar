rule win_unidentified_075_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.unidentified_075."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_075"
        malpedia_rule_date = "20220405"
        malpedia_hash = "ecd38294bd47d5589be5cd5490dc8bb4804afc2a"
        malpedia_version = ""
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
        $sequence_0 = { 8b0a e8???????? 8945f8 837df800 }
            // n = 4, score = 200
            //   8b0a                 | mov                 ecx, dword ptr [edx]
            //   e8????????           |                     
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   837df800             | cmp                 dword ptr [ebp - 8], 0

        $sequence_1 = { 8d4de0 e8???????? e9???????? 837dfc00 7419 }
            // n = 5, score = 200
            //   8d4de0               | lea                 ecx, dword ptr [ebp - 0x20]
            //   e8????????           |                     
            //   e9????????           |                     
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0
            //   7419                 | je                  0x1b

        $sequence_2 = { b930000000 66894dd2 ba78000000 668955d4 b825000000 }
            // n = 5, score = 200
            //   b930000000           | mov                 ecx, 0x30
            //   66894dd2             | mov                 word ptr [ebp - 0x2e], cx
            //   ba78000000           | mov                 edx, 0x78
            //   668955d4             | mov                 word ptr [ebp - 0x2c], dx
            //   b825000000           | mov                 eax, 0x25

        $sequence_3 = { 8b55f4 52 e8???????? 8b45fc 8b880c020000 894dec }
            // n = 6, score = 200
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   52                   | push                edx
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b880c020000         | mov                 ecx, dword ptr [eax + 0x20c]
            //   894dec               | mov                 dword ptr [ebp - 0x14], ecx

        $sequence_4 = { 50 8d8dbceeffff 51 e8???????? 6a00 8d95a4e2ffff 52 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   8d8dbceeffff         | lea                 ecx, dword ptr [ebp - 0x1144]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   6a00                 | push                0
            //   8d95a4e2ffff         | lea                 edx, dword ptr [ebp - 0x1d5c]
            //   52                   | push                edx

        $sequence_5 = { eb00 837df400 7409 8b45f4 }
            // n = 4, score = 200
            //   eb00                 | jmp                 2
            //   837df400             | cmp                 dword ptr [ebp - 0xc], 0
            //   7409                 | je                  0xb
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_6 = { 6800000020 6aff 8b4dec 51 8d55bc 52 }
            // n = 6, score = 200
            //   6800000020           | push                0x20000000
            //   6aff                 | push                -1
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   51                   | push                ecx
            //   8d55bc               | lea                 edx, dword ptr [ebp - 0x44]
            //   52                   | push                edx

        $sequence_7 = { 8b55e0 895108 8b45fc c7400c00000000 6830750000 8b4dfc 51 }
            // n = 7, score = 200
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]
            //   895108               | mov                 dword ptr [ecx + 8], edx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   c7400c00000000       | mov                 dword ptr [eax + 0xc], 0
            //   6830750000           | push                0x7530
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   51                   | push                ecx

        $sequence_8 = { 66898d66ffffff ba53000000 66899568ffffff b861000000 }
            // n = 4, score = 200
            //   66898d66ffffff       | mov                 word ptr [ebp - 0x9a], cx
            //   ba53000000           | mov                 edx, 0x53
            //   66899568ffffff       | mov                 word ptr [ebp - 0x98], dx
            //   b861000000           | mov                 eax, 0x61

        $sequence_9 = { 8d45ac 50 8d8dccf2ffff 51 }
            // n = 4, score = 200
            //   8d45ac               | lea                 eax, dword ptr [ebp - 0x54]
            //   50                   | push                eax
            //   8d8dccf2ffff         | lea                 ecx, dword ptr [ebp - 0xd34]
            //   51                   | push                ecx

    condition:
        7 of them and filesize < 393216
}