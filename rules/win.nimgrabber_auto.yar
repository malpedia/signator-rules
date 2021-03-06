rule win_nimgrabber_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.nimgrabber."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nimgrabber"
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
        $sequence_0 = { 8d148500000000 8b45f0 01d0 8945f4 836df404 8b45f4 8b00 }
            // n = 7, score = 200
            //   8d148500000000       | lea                 edx, [eax*4]
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   01d0                 | add                 eax, edx
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   836df404             | sub                 dword ptr [ebp - 0xc], 4
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8b00                 | mov                 eax, dword ptr [eax]

        $sequence_1 = { 39c2 0f83bd040000 8b442420 8b00 39c6 0f83b5030000 8b430c }
            // n = 7, score = 200
            //   39c2                 | cmp                 edx, eax
            //   0f83bd040000         | jae                 0x4c3
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   39c6                 | cmp                 esi, eax
            //   0f83b5030000         | jae                 0x3bb
            //   8b430c               | mov                 eax, dword ptr [ebx + 0xc]

        $sequence_2 = { e8???????? 8b06 b95c220000 8b10 8d541008 66890a c6420200 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   b95c220000           | mov                 ecx, 0x225c
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   8d541008             | lea                 edx, [eax + edx + 8]
            //   66890a               | mov                 word ptr [edx], cx
            //   c6420200             | mov                 byte ptr [edx + 2], 0

        $sequence_3 = { 8d148508000000 a3???????? e8???????? c7400401000000 8d6808 a1???????? 892c24 }
            // n = 7, score = 200
            //   8d148508000000       | lea                 edx, [eax*4 + 8]
            //   a3????????           |                     
            //   e8????????           |                     
            //   c7400401000000       | mov                 dword ptr [eax + 4], 1
            //   8d6808               | lea                 ebp, [eax + 8]
            //   a1????????           |                     
            //   892c24               | mov                 dword ptr [esp], ebp

        $sequence_4 = { 83e901 893424 894c2404 e8???????? e9???????? 83e901 893c24 }
            // n = 7, score = 200
            //   83e901               | sub                 ecx, 1
            //   893424               | mov                 dword ptr [esp], esi
            //   894c2404             | mov                 dword ptr [esp + 4], ecx
            //   e8????????           |                     
            //   e9????????           |                     
            //   83e901               | sub                 ecx, 1
            //   893c24               | mov                 dword ptr [esp], edi

        $sequence_5 = { 85c0 747b 8b30 85f6 7e75 897588 bfffffffff }
            // n = 7, score = 200
            //   85c0                 | test                eax, eax
            //   747b                 | je                  0x7d
            //   8b30                 | mov                 esi, dword ptr [eax]
            //   85f6                 | test                esi, esi
            //   7e75                 | jle                 0x77
            //   897588               | mov                 dword ptr [ebp - 0x78], esi
            //   bfffffffff           | mov                 edi, 0xffffffff

        $sequence_6 = { e8???????? 8b8578ffffff 8b4d84 bfffffffff 89580c e8???????? c7459000000000 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8b8578ffffff         | mov                 eax, dword ptr [ebp - 0x88]
            //   8b4d84               | mov                 ecx, dword ptr [ebp - 0x7c]
            //   bfffffffff           | mov                 edi, 0xffffffff
            //   89580c               | mov                 dword ptr [eax + 0xc], ebx
            //   e8????????           |                     
            //   c7459000000000       | mov                 dword ptr [ebp - 0x70], 0

        $sequence_7 = { c9 c3 55 89e5 83ec14 c745f800000000 8b4508 }
            // n = 7, score = 200
            //   c9                   | leave               
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   83ec14               | sub                 esp, 0x14
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_8 = { 53 83ec1c 85c9 0f84f7000000 8b5104 89cb 89d0 }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   83ec1c               | sub                 esp, 0x1c
            //   85c9                 | test                ecx, ecx
            //   0f84f7000000         | je                  0xfd
            //   8b5104               | mov                 edx, dword ptr [ecx + 4]
            //   89cb                 | mov                 ebx, ecx
            //   89d0                 | mov                 eax, edx

        $sequence_9 = { 8b4c2434 8b442424 e9???????? 89442424 e8???????? 8b442424 e9???????? }
            // n = 7, score = 200
            //   8b4c2434             | mov                 ecx, dword ptr [esp + 0x34]
            //   8b442424             | mov                 eax, dword ptr [esp + 0x24]
            //   e9????????           |                     
            //   89442424             | mov                 dword ptr [esp + 0x24], eax
            //   e8????????           |                     
            //   8b442424             | mov                 eax, dword ptr [esp + 0x24]
            //   e9????????           |                     

    condition:
        7 of them and filesize < 1238016
}