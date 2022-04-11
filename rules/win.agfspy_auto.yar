rule win_agfspy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.agfspy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.agfspy"
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
        $sequence_0 = { 85c0 750b 8b4508 89430c e9???????? 8b33 8d4df0 }
            // n = 7, score = 300
            //   85c0                 | test                eax, eax
            //   750b                 | jne                 0xd
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   89430c               | mov                 dword ptr [ebx + 0xc], eax
            //   e9????????           |                     
            //   8b33                 | mov                 esi, dword ptr [ebx]
            //   8d4df0               | lea                 ecx, dword ptr [ebp - 0x10]

        $sequence_1 = { e8???????? 8845e4 c745fc01000000 84c0 7479 8b4510 85c0 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   8845e4               | mov                 byte ptr [ebp - 0x1c], al
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   84c0                 | test                al, al
            //   7479                 | je                  0x7b
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   85c0                 | test                eax, eax

        $sequence_2 = { 7713 83ff10 894ddc 8d45cc 0f4345cc c6040800 }
            // n = 6, score = 300
            //   7713                 | ja                  0x15
            //   83ff10               | cmp                 edi, 0x10
            //   894ddc               | mov                 dword ptr [ebp - 0x24], ecx
            //   8d45cc               | lea                 eax, dword ptr [ebp - 0x34]
            //   0f4345cc             | cmovae              eax, dword ptr [ebp - 0x34]
            //   c6040800             | mov                 byte ptr [eax + ecx], 0

        $sequence_3 = { 8d45f4 64a300000000 894dd4 8b5518 c745fc00000000 85d2 0f84eb000000 }
            // n = 7, score = 300
            //   8d45f4               | lea                 eax, dword ptr [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   894dd4               | mov                 dword ptr [ebp - 0x2c], ecx
            //   8b5518               | mov                 edx, dword ptr [ebp + 0x18]
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   85d2                 | test                edx, edx
            //   0f84eb000000         | je                  0xf1

        $sequence_4 = { 8945e0 8b45b8 8945e4 8b45bc 8945ec 8b45c0 }
            // n = 6, score = 300
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   8b45b8               | mov                 eax, dword ptr [ebp - 0x48]
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8b45bc               | mov                 eax, dword ptr [ebp - 0x44]
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8b45c0               | mov                 eax, dword ptr [ebp - 0x40]

        $sequence_5 = { 7de0 80fa2e 7538 8b7e44 894648 3bc7 }
            // n = 6, score = 300
            //   7de0                 | jge                 0xffffffe2
            //   80fa2e               | cmp                 dl, 0x2e
            //   7538                 | jne                 0x3a
            //   8b7e44               | mov                 edi, dword ptr [esi + 0x44]
            //   894648               | mov                 dword ptr [esi + 0x48], eax
            //   3bc7                 | cmp                 eax, edi

        $sequence_6 = { 8945d0 c6462c00 a801 7415 8a4b0c 8d45d7 80c901 }
            // n = 7, score = 300
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax
            //   c6462c00             | mov                 byte ptr [esi + 0x2c], 0
            //   a801                 | test                al, 1
            //   7415                 | je                  0x17
            //   8a4b0c               | mov                 cl, byte ptr [ebx + 0xc]
            //   8d45d7               | lea                 eax, dword ptr [ebp - 0x29]
            //   80c901               | or                  cl, 1

        $sequence_7 = { 0f86f5010000 50 e8???????? 83c404 85c0 0f84e9010000 8b4dec }
            // n = 7, score = 300
            //   0f86f5010000         | jbe                 0x1fb
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax
            //   0f84e9010000         | je                  0x1ef
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]

        $sequence_8 = { 83c40c 894e04 8b4df4 5f 5b 8b490c 894e0c }
            // n = 7, score = 300
            //   83c40c               | add                 esp, 0xc
            //   894e04               | mov                 dword ptr [esi + 4], ecx
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx
            //   8b490c               | mov                 ecx, dword ptr [ecx + 0xc]
            //   894e0c               | mov                 dword ptr [esi + 0xc], ecx

        $sequence_9 = { e8???????? 8bf0 895f10 8b45fc 8bcb 894714 8bfe }
            // n = 7, score = 300
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   895f10               | mov                 dword ptr [edi + 0x10], ebx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8bcb                 | mov                 ecx, ebx
            //   894714               | mov                 dword ptr [edi + 0x14], eax
            //   8bfe                 | mov                 edi, esi

    condition:
        7 of them and filesize < 1482752
}