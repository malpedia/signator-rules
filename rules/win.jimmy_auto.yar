rule win_jimmy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.jimmy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.jimmy"
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
        $sequence_0 = { 763d ff750c e8???????? 59 8945fc }
            // n = 5, score = 400
            //   763d                 | jbe                 0x3f
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_1 = { 668945fa 68b4000000 8d8548ffffff 50 e8???????? 59 59 }
            // n = 7, score = 400
            //   668945fa             | mov                 word ptr [ebp - 6], ax
            //   68b4000000           | push                0xb4
            //   8d8548ffffff         | lea                 eax, dword ptr [ebp - 0xb8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx

        $sequence_2 = { 6a02 e8???????? 59 59 8985ccfdffff 83bdccfdffffff 7508 }
            // n = 7, score = 400
            //   6a02                 | push                2
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   8985ccfdffff         | mov                 dword ptr [ebp - 0x234], eax
            //   83bdccfdffffff       | cmp                 dword ptr [ebp - 0x234], -1
            //   7508                 | jne                 0xa

        $sequence_3 = { 668945d2 33c0 668945d4 6a25 58 }
            // n = 5, score = 400
            //   668945d2             | mov                 word ptr [ebp - 0x2e], ax
            //   33c0                 | xor                 eax, eax
            //   668945d4             | mov                 word ptr [ebp - 0x2c], ax
            //   6a25                 | push                0x25
            //   58                   | pop                 eax

        $sequence_4 = { ff7508 ffb5c0fdffff e8???????? 59 }
            // n = 4, score = 400
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ffb5c0fdffff         | push                dword ptr [ebp - 0x240]
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_5 = { 8945f0 8b45fc 8b4df0 894814 837df000 7502 }
            // n = 6, score = 400
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   894814               | mov                 dword ptr [eax + 0x14], ecx
            //   837df000             | cmp                 dword ptr [ebp - 0x10], 0
            //   7502                 | jne                 4

        $sequence_6 = { e8???????? 83c414 8945f8 6a40 6800300000 68dc020000 6a00 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   6a40                 | push                0x40
            //   6800300000           | push                0x3000
            //   68dc020000           | push                0x2dc
            //   6a00                 | push                0

        $sequence_7 = { 83c414 8945f8 6a40 6800300000 68dc020000 6a00 ff750c }
            // n = 7, score = 400
            //   83c414               | add                 esp, 0x14
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   6a40                 | push                0x40
            //   6800300000           | push                0x3000
            //   68dc020000           | push                0x2dc
            //   6a00                 | push                0
            //   ff750c               | push                dword ptr [ebp + 0xc]

        $sequence_8 = { 898574feffff 83bd74feffff00 0f84a5000000 81bd74feffffcb000000 0f8495000000 ff7508 e8???????? }
            // n = 7, score = 400
            //   898574feffff         | mov                 dword ptr [ebp - 0x18c], eax
            //   83bd74feffff00       | cmp                 dword ptr [ebp - 0x18c], 0
            //   0f84a5000000         | je                  0xab
            //   81bd74feffffcb000000     | cmp    dword ptr [ebp - 0x18c], 0xcb
            //   0f8495000000         | je                  0x9b
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     

        $sequence_9 = { 8985b0feffff e9???????? 6a16 8d85ccfeffff 50 e8???????? 59 }
            // n = 7, score = 400
            //   8985b0feffff         | mov                 dword ptr [ebp - 0x150], eax
            //   e9????????           |                     
            //   6a16                 | push                0x16
            //   8d85ccfeffff         | lea                 eax, dword ptr [ebp - 0x134]
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx

    condition:
        7 of them and filesize < 188416
}