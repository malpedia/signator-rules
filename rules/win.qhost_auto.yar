rule win_qhost_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.qhost."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.qhost"
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
        $sequence_0 = { 8b5508 0355fc 0fbe02 83f86e 7c45 }
            // n = 5, score = 100
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   0355fc               | add                 edx, dword ptr [ebp - 4]
            //   0fbe02               | movsx               eax, byte ptr [edx]
            //   83f86e               | cmp                 eax, 0x6e
            //   7c45                 | jl                  0x47

        $sequence_1 = { 8b95c8fbffff 52 ff15???????? 33c0 e9???????? e9???????? }
            // n = 6, score = 100
            //   8b95c8fbffff         | mov                 edx, dword ptr [ebp - 0x438]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   e9????????           |                     

        $sequence_2 = { 0f85e9010000 8d85dcbeffff 50 8d8d3cbeffff 51 8d95ecbfffff 52 }
            // n = 7, score = 100
            //   0f85e9010000         | jne                 0x1ef
            //   8d85dcbeffff         | lea                 eax, [ebp - 0x4124]
            //   50                   | push                eax
            //   8d8d3cbeffff         | lea                 ecx, [ebp - 0x41c4]
            //   51                   | push                ecx
            //   8d95ecbfffff         | lea                 edx, [ebp - 0x4014]
            //   52                   | push                edx

        $sequence_3 = { 6a5c 8d85f4fdffff 50 ff15???????? 83c408 83c001 }
            // n = 6, score = 100
            //   6a5c                 | push                0x5c
            //   8d85f4fdffff         | lea                 eax, [ebp - 0x20c]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c408               | add                 esp, 8
            //   83c001               | add                 eax, 1

        $sequence_4 = { 83c408 f7d8 1bc0 40 884590 }
            // n = 5, score = 100
            //   83c408               | add                 esp, 8
            //   f7d8                 | neg                 eax
            //   1bc0                 | sbb                 eax, eax
            //   40                   | inc                 eax
            //   884590               | mov                 byte ptr [ebp - 0x70], al

        $sequence_5 = { 837df800 741e 8b45fc 50 68???????? 68???????? ff15???????? }
            // n = 7, score = 100
            //   837df800             | cmp                 dword ptr [ebp - 8], 0
            //   741e                 | je                  0x20
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax
            //   68????????           |                     
            //   68????????           |                     
            //   ff15????????         |                     

        $sequence_6 = { c745fc00000000 c745f800000000 837d0c00 7406 837d1000 }
            // n = 5, score = 100
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0
            //   837d0c00             | cmp                 dword ptr [ebp + 0xc], 0
            //   7406                 | je                  8
            //   837d1000             | cmp                 dword ptr [ebp + 0x10], 0

        $sequence_7 = { 52 8b45fc 50 ff15???????? eb4a }
            // n = 5, score = 100
            //   52                   | push                edx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   eb4a                 | jmp                 0x4c

        $sequence_8 = { 83c430 8d9590f8ffff 52 e8???????? 83c404 }
            // n = 5, score = 100
            //   83c430               | add                 esp, 0x30
            //   8d9590f8ffff         | lea                 edx, [ebp - 0x770]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_9 = { 837df800 7421 8b55fc 52 68???????? }
            // n = 5, score = 100
            //   837df800             | cmp                 dword ptr [ebp - 8], 0
            //   7421                 | je                  0x23
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   52                   | push                edx
            //   68????????           |                     

    condition:
        7 of them and filesize < 286720
}