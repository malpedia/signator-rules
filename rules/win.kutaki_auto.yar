rule win_kutaki_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.kutaki."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kutaki"
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
        $sequence_0 = { 57 53 8975dc 8975d8 8975d4 8975d0 8975c0 }
            // n = 7, score = 700
            //   57                   | push                edi
            //   53                   | push                ebx
            //   8975dc               | mov                 dword ptr [ebp - 0x24], esi
            //   8975d8               | mov                 dword ptr [ebp - 0x28], esi
            //   8975d4               | mov                 dword ptr [ebp - 0x2c], esi
            //   8975d0               | mov                 dword ptr [ebp - 0x30], esi
            //   8975c0               | mov                 dword ptr [ebp - 0x40], esi

        $sequence_1 = { ff15???????? 8985acfeffff 8d55a4 52 8b85acfeffff 8b08 8b95acfeffff }
            // n = 7, score = 700
            //   ff15????????         |                     
            //   8985acfeffff         | mov                 dword ptr [ebp - 0x154], eax
            //   8d55a4               | lea                 edx, [ebp - 0x5c]
            //   52                   | push                edx
            //   8b85acfeffff         | mov                 eax, dword ptr [ebp - 0x154]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8b95acfeffff         | mov                 edx, dword ptr [ebp - 0x154]

        $sequence_2 = { 8d4de0 ff15???????? 8b4d08 6a00 8b11 8955c4 ffd3 }
            // n = 7, score = 700
            //   8d4de0               | lea                 ecx, [ebp - 0x20]
            //   ff15????????         |                     
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   6a00                 | push                0
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   8955c4               | mov                 dword ptr [ebp - 0x3c], edx
            //   ffd3                 | call                ebx

        $sequence_3 = { 6683f97f 0f9ec2 660fb645b0 33c9 663d7f00 0f9ec1 23d1 }
            // n = 7, score = 700
            //   6683f97f             | cmp                 cx, 0x7f
            //   0f9ec2               | setle               dl
            //   660fb645b0           | movzx               ax, byte ptr [ebp - 0x50]
            //   33c9                 | xor                 ecx, ecx
            //   663d7f00             | cmp                 ax, 0x7f
            //   0f9ec1               | setle               cl
            //   23d1                 | and                 edx, ecx

        $sequence_4 = { ffd6 8bd0 b9???????? ffd7 8d45c8 8d4dcc 50 }
            // n = 7, score = 700
            //   ffd6                 | call                esi
            //   8bd0                 | mov                 edx, eax
            //   b9????????           |                     
            //   ffd7                 | call                edi
            //   8d45c8               | lea                 eax, [ebp - 0x38]
            //   8d4dcc               | lea                 ecx, [ebp - 0x34]
            //   50                   | push                eax

        $sequence_5 = { ff15???????? 6a00 6aff 8d8d50ffffff 51 8b55c4 52 }
            // n = 7, score = 700
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6aff                 | push                -1
            //   8d8d50ffffff         | lea                 ecx, [ebp - 0xb0]
            //   51                   | push                ecx
            //   8b55c4               | mov                 edx, dword ptr [ebp - 0x3c]
            //   52                   | push                edx

        $sequence_6 = { 7d1d 6a50 68???????? 8b45bc 50 8b4db8 51 }
            // n = 7, score = 700
            //   7d1d                 | jge                 0x1f
            //   6a50                 | push                0x50
            //   68????????           |                     
            //   8b45bc               | mov                 eax, dword ptr [ebp - 0x44]
            //   50                   | push                eax
            //   8b4db8               | mov                 ecx, dword ptr [ebp - 0x48]
            //   51                   | push                ecx

        $sequence_7 = { c78554ffffff08000000 8d45a4 50 8d4db4 51 8d5594 }
            // n = 6, score = 700
            //   c78554ffffff08000000     | mov    dword ptr [ebp - 0xac], 8
            //   8d45a4               | lea                 eax, [ebp - 0x5c]
            //   50                   | push                eax
            //   8d4db4               | lea                 ecx, [ebp - 0x4c]
            //   51                   | push                ecx
            //   8d5594               | lea                 edx, [ebp - 0x6c]

        $sequence_8 = { ff15???????? 8d55dc 899544ffffff eb09 8d45dc 898544ffffff 8b8d44ffffff }
            // n = 7, score = 700
            //   ff15????????         |                     
            //   8d55dc               | lea                 edx, [ebp - 0x24]
            //   899544ffffff         | mov                 dword ptr [ebp - 0xbc], edx
            //   eb09                 | jmp                 0xb
            //   8d45dc               | lea                 eax, [ebp - 0x24]
            //   898544ffffff         | mov                 dword ptr [ebp - 0xbc], eax
            //   8b8d44ffffff         | mov                 ecx, dword ptr [ebp - 0xbc]

        $sequence_9 = { 898524ffffff 83bd24ffffff00 7d23 6a1c 68???????? 8b8528ffffff }
            // n = 6, score = 700
            //   898524ffffff         | mov                 dword ptr [ebp - 0xdc], eax
            //   83bd24ffffff00       | cmp                 dword ptr [ebp - 0xdc], 0
            //   7d23                 | jge                 0x25
            //   6a1c                 | push                0x1c
            //   68????????           |                     
            //   8b8528ffffff         | mov                 eax, dword ptr [ebp - 0xd8]

    condition:
        7 of them and filesize < 1335296
}