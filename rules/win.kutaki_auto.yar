rule win_kutaki_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.kutaki."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kutaki"
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
        $sequence_0 = { 8b8dc8feffff 51 8b95c4feffff 52 ff15???????? 898540feffff }
            // n = 6, score = 700
            //   8b8dc8feffff         | mov                 ecx, dword ptr [ebp - 0x138]
            //   51                   | push                ecx
            //   8b95c4feffff         | mov                 edx, dword ptr [ebp - 0x13c]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   898540feffff         | mov                 dword ptr [ebp - 0x1c0], eax

        $sequence_1 = { 8d8550ffffff 50 ff15???????? 898558feffff 8d8d68feffff 51 8b9558feffff }
            // n = 7, score = 700
            //   8d8550ffffff         | lea                 eax, dword ptr [ebp - 0xb0]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   898558feffff         | mov                 dword ptr [ebp - 0x1a8], eax
            //   8d8d68feffff         | lea                 ecx, dword ptr [ebp - 0x198]
            //   51                   | push                ecx
            //   8b9558feffff         | mov                 edx, dword ptr [ebp - 0x1a8]

        $sequence_2 = { 8b4d80 f7d9 66894db4 8d4ddc ff15???????? 8d4dd4 }
            // n = 6, score = 700
            //   8b4d80               | mov                 ecx, dword ptr [ebp - 0x80]
            //   f7d9                 | neg                 ecx
            //   66894db4             | mov                 word ptr [ebp - 0x4c], cx
            //   8d4ddc               | lea                 ecx, dword ptr [ebp - 0x24]
            //   ff15????????         |                     
            //   8d4dd4               | lea                 ecx, dword ptr [ebp - 0x2c]

        $sequence_3 = { 8d9574ffffff 52 ff15???????? 8985b8feffff 8d45bc 50 8b8db8feffff }
            // n = 7, score = 700
            //   8d9574ffffff         | lea                 edx, dword ptr [ebp - 0x8c]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8985b8feffff         | mov                 dword ptr [ebp - 0x148], eax
            //   8d45bc               | lea                 eax, dword ptr [ebp - 0x44]
            //   50                   | push                eax
            //   8b8db8feffff         | mov                 ecx, dword ptr [ebp - 0x148]

        $sequence_4 = { 8d5590 52 8d45b0 50 8d4dc0 51 6a06 }
            // n = 7, score = 700
            //   8d5590               | lea                 edx, dword ptr [ebp - 0x70]
            //   52                   | push                edx
            //   8d45b0               | lea                 eax, dword ptr [ebp - 0x50]
            //   50                   | push                eax
            //   8d4dc0               | lea                 ecx, dword ptr [ebp - 0x40]
            //   51                   | push                ecx
            //   6a06                 | push                6

        $sequence_5 = { 68a0000000 68???????? 8b8dd0feffff 51 8b95ccfeffff 52 ff15???????? }
            // n = 7, score = 700
            //   68a0000000           | push                0xa0
            //   68????????           |                     
            //   8b8dd0feffff         | mov                 ecx, dword ptr [ebp - 0x130]
            //   51                   | push                ecx
            //   8b95ccfeffff         | mov                 edx, dword ptr [ebp - 0x134]
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_6 = { 660fb64db8 6683e13f ff15???????? 8845c0 c745fc2b000000 8b45dc 25ff000000 }
            // n = 7, score = 700
            //   660fb64db8           | movzx               cx, byte ptr [ebp - 0x48]
            //   6683e13f             | and                 cx, 0x3f
            //   ff15????????         |                     
            //   8845c0               | mov                 byte ptr [ebp - 0x40], al
            //   c745fc2b000000       | mov                 dword ptr [ebp - 4], 0x2b
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   25ff000000           | and                 eax, 0xff

        $sequence_7 = { ff15???????? 83c414 e9???????? 8b4d10 8b11 52 }
            // n = 6, score = 700
            //   ff15????????         |                     
            //   83c414               | add                 esp, 0x14
            //   e9????????           |                     
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   52                   | push                edx

        $sequence_8 = { 52 ff15???????? 894590 eb07 c7459000000000 8b45dc 50 }
            // n = 7, score = 700
            //   52                   | push                edx
            //   ff15????????         |                     
            //   894590               | mov                 dword ptr [ebp - 0x70], eax
            //   eb07                 | jmp                 9
            //   c7459000000000       | mov                 dword ptr [ebp - 0x70], 0
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   50                   | push                eax

        $sequence_9 = { ff15???????? 8d4dcc ff15???????? c745fc0a000000 8b55d0 52 }
            // n = 6, score = 700
            //   ff15????????         |                     
            //   8d4dcc               | lea                 ecx, dword ptr [ebp - 0x34]
            //   ff15????????         |                     
            //   c745fc0a000000       | mov                 dword ptr [ebp - 4], 0xa
            //   8b55d0               | mov                 edx, dword ptr [ebp - 0x30]
            //   52                   | push                edx

    condition:
        7 of them and filesize < 1335296
}