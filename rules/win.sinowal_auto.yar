rule win_sinowal_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.sinowal."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sinowal"
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
        $sequence_0 = { 8b4508 50 e8???????? 83c404 8945fc 837dfc00 741a }
            // n = 7, score = 200
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0
            //   741a                 | je                  0x1c

        $sequence_1 = { 8b5510 52 8d45ec 50 8d8de8feffff 51 }
            // n = 6, score = 200
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   52                   | push                edx
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   50                   | push                eax
            //   8d8de8feffff         | lea                 ecx, [ebp - 0x118]
            //   51                   | push                ecx

        $sequence_2 = { 6800000080 8d55fc 52 e8???????? 8985b8feffff 83bdb8feffff00 }
            // n = 6, score = 200
            //   6800000080           | push                0x80000000
            //   8d55fc               | lea                 edx, [ebp - 4]
            //   52                   | push                edx
            //   e8????????           |                     
            //   8985b8feffff         | mov                 dword ptr [ebp - 0x148], eax
            //   83bdb8feffff00       | cmp                 dword ptr [ebp - 0x148], 0

        $sequence_3 = { 89858afdffff 89858efdffff 898592fdffff 898596fdffff 89859afdffff 89859efdffff }
            // n = 6, score = 200
            //   89858afdffff         | mov                 dword ptr [ebp - 0x276], eax
            //   89858efdffff         | mov                 dword ptr [ebp - 0x272], eax
            //   898592fdffff         | mov                 dword ptr [ebp - 0x26e], eax
            //   898596fdffff         | mov                 dword ptr [ebp - 0x26a], eax
            //   89859afdffff         | mov                 dword ptr [ebp - 0x266], eax
            //   89859efdffff         | mov                 dword ptr [ebp - 0x262], eax

        $sequence_4 = { 890c95d0669600 8b55fc 83c201 8955fc 817dfc70020000 7c11 }
            // n = 6, score = 200
            //   890c95d0669600       | mov                 dword ptr [edx*4 + 0x9666d0], ecx
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   83c201               | add                 edx, 1
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   817dfc70020000       | cmp                 dword ptr [ebp - 4], 0x270
            //   7c11                 | jl                  0x13

        $sequence_5 = { 837df800 750a b805400080 e9???????? 8b5510 52 8b450c }
            // n = 7, score = 200
            //   837df800             | cmp                 dword ptr [ebp - 8], 0
            //   750a                 | jne                 0xc
            //   b805400080           | mov                 eax, 0x80004005
            //   e9????????           |                     
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   52                   | push                edx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_6 = { 68???????? 6a00 8d45f4 50 ff15???????? 85c0 7508 }
            // n = 7, score = 200
            //   68????????           |                     
            //   6a00                 | push                0
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7508                 | jne                 0xa

        $sequence_7 = { 8b450c 33d2 b908000000 f7f1 85d2 740a }
            // n = 6, score = 200
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   33d2                 | xor                 edx, edx
            //   b908000000           | mov                 ecx, 8
            //   f7f1                 | div                 ecx
            //   85d2                 | test                edx, edx
            //   740a                 | je                  0xc

        $sequence_8 = { 330c85d0669600 8b55f4 8b4508 030c90 034df4 8b55fc }
            // n = 6, score = 200
            //   330c85d0669600       | xor                 ecx, dword ptr [eax*4 + 0x9666d0]
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   030c90               | add                 ecx, dword ptr [eax + edx*4]
            //   034df4               | add                 ecx, dword ptr [ebp - 0xc]
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]

        $sequence_9 = { 83c408 83bd50fdffff00 740b 8b45f8 8b55fc }
            // n = 5, score = 200
            //   83c408               | add                 esp, 8
            //   83bd50fdffff00       | cmp                 dword ptr [ebp - 0x2b0], 0
            //   740b                 | je                  0xd
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]

    condition:
        7 of them and filesize < 73728
}