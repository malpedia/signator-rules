rule win_urausy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.urausy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.urausy"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
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
        $sequence_0 = { 6a00 68???????? 68???????? ff7508 e8???????? 6a00 ff35???????? }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   68????????           |                     
            //   68????????           |                     
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   6a00                 | push                0
            //   ff35????????         |                     

        $sequence_1 = { 8bd3 81c2a5000000 50 53 52 51 }
            // n = 6, score = 200
            //   8bd3                 | mov                 edx, ebx
            //   81c2a5000000         | add                 edx, 0xa5
            //   50                   | push                eax
            //   53                   | push                ebx
            //   52                   | push                edx
            //   51                   | push                ecx

        $sequence_2 = { ff75e4 e8???????? 8945e8 ff35???????? }
            // n = 4, score = 200
            //   ff75e4               | push                dword ptr [ebp - 0x1c]
            //   e8????????           |                     
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   ff35????????         |                     

        $sequence_3 = { 6a01 ff35???????? e8???????? 6a00 68???????? 68???????? }
            // n = 6, score = 200
            //   6a01                 | push                1
            //   ff35????????         |                     
            //   e8????????           |                     
            //   6a00                 | push                0
            //   68????????           |                     
            //   68????????           |                     

        $sequence_4 = { c21000 55 8bec 81c4ecefffff }
            // n = 4, score = 200
            //   c21000               | ret                 0x10
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81c4ecefffff         | add                 esp, 0xffffefec

        $sequence_5 = { 0f8585000000 6814000000 68???????? 6a04 8d8500fcffff 50 e8???????? }
            // n = 7, score = 200
            //   0f8585000000         | jne                 0x8b
            //   6814000000           | push                0x14
            //   68????????           |                     
            //   6a04                 | push                4
            //   8d8500fcffff         | lea                 eax, [ebp - 0x400]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_6 = { 8d85dcf7ffff 50 57 56 }
            // n = 4, score = 200
            //   8d85dcf7ffff         | lea                 eax, [ebp - 0x824]
            //   50                   | push                eax
            //   57                   | push                edi
            //   56                   | push                esi

        $sequence_7 = { 833d????????00 0f8fae050000 c705????????01000000 ff35???????? 8f45f0 ff35???????? 8f45f4 }
            // n = 7, score = 200
            //   833d????????00       |                     
            //   0f8fae050000         | jg                  0x5b4
            //   c705????????01000000     |     
            //   ff35????????         |                     
            //   8f45f0               | pop                 dword ptr [ebp - 0x10]
            //   ff35????????         |                     
            //   8f45f4               | pop                 dword ptr [ebp - 0xc]

        $sequence_8 = { e8???????? ff75fc e8???????? 8b45f8 c9 c20400 ff25???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   c9                   | leave               
            //   c20400               | ret                 4
            //   ff25????????         |                     

        $sequence_9 = { e8???????? b800000000 c9 c21400 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   b800000000           | mov                 eax, 0
            //   c9                   | leave               
            //   c21400               | ret                 0x14

    condition:
        7 of them and filesize < 98304
}