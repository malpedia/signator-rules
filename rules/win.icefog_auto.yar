rule win_icefog_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.icefog."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.icefog"
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
        $sequence_0 = { 8bca 8b9590feffff 8908 e9???????? 807e1400 0f85b4d3ffff 8b16 }
            // n = 7, score = 200
            //   8bca                 | mov                 ecx, edx
            //   8b9590feffff         | mov                 edx, dword ptr [ebp - 0x170]
            //   8908                 | mov                 dword ptr [eax], ecx
            //   e9????????           |                     
            //   807e1400             | cmp                 byte ptr [esi + 0x14], 0
            //   0f85b4d3ffff         | jne                 0xffffd3ba
            //   8b16                 | mov                 edx, dword ptr [esi]

        $sequence_1 = { 8b55f4 52 8bf8 e8???????? 83c414 b801000000 014310 }
            // n = 7, score = 200
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   52                   | push                edx
            //   8bf8                 | mov                 edi, eax
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   b801000000           | mov                 eax, 1
            //   014310               | add                 dword ptr [ebx + 0x10], eax

        $sequence_2 = { 8bd7 e8???????? 8b4df8 66890471 0fb75710 46 3bf2 }
            // n = 7, score = 200
            //   8bd7                 | mov                 edx, edi
            //   e8????????           |                     
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   66890471             | mov                 word ptr [ecx + esi*2], ax
            //   0fb75710             | movzx               edx, word ptr [edi + 0x10]
            //   46                   | inc                 esi
            //   3bf2                 | cmp                 esi, edx

        $sequence_3 = { 8b4e4c 6a00 8d04bf 8d04c1 53 50 89852cffffff }
            // n = 7, score = 200
            //   8b4e4c               | mov                 ecx, dword ptr [esi + 0x4c]
            //   6a00                 | push                0
            //   8d04bf               | lea                 eax, dword ptr [edi + edi*4]
            //   8d04c1               | lea                 eax, dword ptr [ecx + eax*8]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   89852cffffff         | mov                 dword ptr [ebp - 0xd4], eax

        $sequence_4 = { 894580 894584 894588 89458c 894590 89bd70ffffff 8975d8 }
            // n = 7, score = 200
            //   894580               | mov                 dword ptr [ebp - 0x80], eax
            //   894584               | mov                 dword ptr [ebp - 0x7c], eax
            //   894588               | mov                 dword ptr [ebp - 0x78], eax
            //   89458c               | mov                 dword ptr [ebp - 0x74], eax
            //   894590               | mov                 dword ptr [ebp - 0x70], eax
            //   89bd70ffffff         | mov                 dword ptr [ebp - 0x90], edi
            //   8975d8               | mov                 dword ptr [ebp - 0x28], esi

        $sequence_5 = { 8bec a1???????? 56 8b750c 57 50 83c6ec }
            // n = 7, score = 200
            //   8bec                 | mov                 ebp, esp
            //   a1????????           |                     
            //   56                   | push                esi
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   57                   | push                edi
            //   50                   | push                eax
            //   83c6ec               | add                 esi, -0x14

        $sequence_6 = { 8b45f8 50 e8???????? 83c404 a900040000 7562 8b4df8 }
            // n = 7, score = 200
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   a900040000           | test                eax, 0x400
            //   7562                 | jne                 0x64
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]

        $sequence_7 = { e8???????? 83c42c 837e0800 7d06 837e1400 7506 837df400 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c42c               | add                 esp, 0x2c
            //   837e0800             | cmp                 dword ptr [esi + 8], 0
            //   7d06                 | jge                 8
            //   837e1400             | cmp                 dword ptr [esi + 0x14], 0
            //   7506                 | jne                 8
            //   837df400             | cmp                 dword ptr [ebp - 0xc], 0

        $sequence_8 = { 50 e8???????? 83c408 8d9b00000000 8b45f8 8945f4 85c0 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8d9b00000000         | lea                 ebx, dword ptr [ebx]
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   85c0                 | test                eax, eax

        $sequence_9 = { 85ff 750d 8bc3 e8???????? 8bf8 85ff 7408 }
            // n = 7, score = 200
            //   85ff                 | test                edi, edi
            //   750d                 | jne                 0xf
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi
            //   7408                 | je                  0xa

    condition:
        7 of them and filesize < 1187840
}