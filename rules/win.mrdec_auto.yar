rule win_mrdec_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.mrdec."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mrdec"
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
        $sequence_0 = { 7308 c1e805 c1e005 eb0c 3d00001000 7605 }
            // n = 6, score = 100
            //   7308                 | jae                 0xa
            //   c1e805               | shr                 eax, 5
            //   c1e005               | shl                 eax, 5
            //   eb0c                 | jmp                 0xe
            //   3d00001000           | cmp                 eax, 0x100000
            //   7605                 | jbe                 7

        $sequence_1 = { ff35???????? e8???????? 6a00 ff75d8 e8???????? 6814010000 68???????? }
            // n = 7, score = 100
            //   ff35????????         |                     
            //   e8????????           |                     
            //   6a00                 | push                0
            //   ff75d8               | push                dword ptr [ebp - 0x28]
            //   e8????????           |                     
            //   6814010000           | push                0x114
            //   68????????           |                     

        $sequence_2 = { 50 e8???????? 8145ec58020000 8d45f0 50 8d45e8 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   8145ec58020000       | add                 dword ptr [ebp - 0x14], 0x258
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax
            //   8d45e8               | lea                 eax, [ebp - 0x18]

        $sequence_3 = { e8???????? c9 c20400 55 8bec 81c4e4feffff }
            // n = 6, score = 100
            //   e8????????           |                     
            //   c9                   | leave               
            //   c20400               | ret                 4
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81c4e4feffff         | add                 esp, 0xfffffee4

        $sequence_4 = { 8d45e0 50 ff7508 6a00 6a00 6a02 e8???????? }
            // n = 7, score = 100
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a02                 | push                2
            //   e8????????           |                     

        $sequence_5 = { 8d45fc 50 68???????? 6a00 6a00 6a00 ff75f4 }
            // n = 7, score = 100
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   68????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff75f4               | push                dword ptr [ebp - 0xc]

        $sequence_6 = { e8???????? 59 51 80c141 884808 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   51                   | push                ecx
            //   80c141               | add                 cl, 0x41
            //   884808               | mov                 byte ptr [eax + 8], cl

        $sequence_7 = { 68???????? e8???????? 85c0 0f84b7000000 57 e8???????? 83f819 }
            // n = 7, score = 100
            //   68????????           |                     
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f84b7000000         | je                  0xbd
            //   57                   | push                edi
            //   e8????????           |                     
            //   83f819               | cmp                 eax, 0x19

        $sequence_8 = { ff75e0 e8???????? ff75e0 e8???????? 6a00 6a00 }
            // n = 6, score = 100
            //   ff75e0               | push                dword ptr [ebp - 0x20]
            //   e8????????           |                     
            //   ff75e0               | push                dword ptr [ebp - 0x20]
            //   e8????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_9 = { 6a00 ff75ec e8???????? ebd2 c745e42c000000 }
            // n = 5, score = 100
            //   6a00                 | push                0
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   e8????????           |                     
            //   ebd2                 | jmp                 0xffffffd4
            //   c745e42c000000       | mov                 dword ptr [ebp - 0x1c], 0x2c

    condition:
        7 of them and filesize < 44864
}