rule win_kronos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.kronos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kronos"
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
        $sequence_0 = { ff15???????? 85c0 0f8cf0000000 6a04 56 6a02 8d45cc }
            // n = 7, score = 2800
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f8cf0000000         | jl                  0xf6
            //   6a04                 | push                4
            //   56                   | push                esi
            //   6a02                 | push                2
            //   8d45cc               | lea                 eax, [ebp - 0x34]

        $sequence_1 = { f6c240 0f85be020000 b901000000 894d0c 8bca 8b550c d3e2 }
            // n = 7, score = 2800
            //   f6c240               | test                dl, 0x40
            //   0f85be020000         | jne                 0x2c4
            //   b901000000           | mov                 ecx, 1
            //   894d0c               | mov                 dword ptr [ebp + 0xc], ecx
            //   8bca                 | mov                 ecx, edx
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   d3e2                 | shl                 edx, cl

        $sequence_2 = { c20c00 2bf9 c686d800000001 8d0419 7514 8b4508 8938 }
            // n = 7, score = 2800
            //   c20c00               | ret                 0xc
            //   2bf9                 | sub                 edi, ecx
            //   c686d800000001       | mov                 byte ptr [esi + 0xd8], 1
            //   8d0419               | lea                 eax, [ecx + ebx]
            //   7514                 | jne                 0x16
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8938                 | mov                 dword ptr [eax], edi

        $sequence_3 = { 85c0 7406 8b4e04 894804 3b75f0 7505 }
            // n = 6, score = 2800
            //   85c0                 | test                eax, eax
            //   7406                 | je                  8
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   894804               | mov                 dword ptr [eax + 4], ecx
            //   3b75f0               | cmp                 esi, dword ptr [ebp - 0x10]
            //   7505                 | jne                 7

        $sequence_4 = { 8b44241c 51 8b4d08 52 50 51 e8???????? }
            // n = 7, score = 2800
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   51                   | push                ecx
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   52                   | push                edx
            //   50                   | push                eax
            //   51                   | push                ecx
            //   e8????????           |                     

        $sequence_5 = { 83ec20 8b4510 8b4d0c 8945f8 33c0 }
            // n = 5, score = 2800
            //   83ec20               | sub                 esp, 0x20
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   33c0                 | xor                 eax, eax

        $sequence_6 = { ff15???????? 50 6a40 ff15???????? 8bf0 57 }
            // n = 6, score = 2800
            //   ff15????????         |                     
            //   50                   | push                eax
            //   6a40                 | push                0x40
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   57                   | push                edi

        $sequence_7 = { 8b4d0c 891e 895e04 895e08 8bd1 385f05 }
            // n = 6, score = 2800
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   891e                 | mov                 dword ptr [esi], ebx
            //   895e04               | mov                 dword ptr [esi + 4], ebx
            //   895e08               | mov                 dword ptr [esi + 8], ebx
            //   8bd1                 | mov                 edx, ecx
            //   385f05               | cmp                 byte ptr [edi + 5], bl

        $sequence_8 = { ffd7 8bf0 85f6 74e9 6a00 6a01 6a02 }
            // n = 7, score = 2800
            //   ffd7                 | call                edi
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   74e9                 | je                  0xffffffeb
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   6a02                 | push                2

        $sequence_9 = { 7559 8d45a4 50 6a06 e8???????? 8d85d8feffff 50 }
            // n = 7, score = 2800
            //   7559                 | jne                 0x5b
            //   8d45a4               | lea                 eax, [ebp - 0x5c]
            //   50                   | push                eax
            //   6a06                 | push                6
            //   e8????????           |                     
            //   8d85d8feffff         | lea                 eax, [ebp - 0x128]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 1302528
}