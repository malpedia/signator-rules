rule win_breakthrough_loader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.breakthrough_loader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.breakthrough_loader"
        malpedia_rule_date = "20211007"
        malpedia_hash = "e5b790e0f888f252d49063a1251ca60ec2832535"
        malpedia_version = "20211008"
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
        $sequence_0 = { 83e03f 8bd6 c1fa06 6bc830 8b049540354500 }
            // n = 5, score = 100
            //   83e03f               | and                 eax, 0x3f
            //   8bd6                 | mov                 edx, esi
            //   c1fa06               | sar                 edx, 6
            //   6bc830               | imul                ecx, eax, 0x30
            //   8b049540354500       | mov                 eax, dword ptr [edx*4 + 0x453540]

        $sequence_1 = { 8b4dfc 894e10 837e1410 7204 8b06 eb02 8bc6 }
            // n = 7, score = 100
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   894e10               | mov                 dword ptr [esi + 0x10], ecx
            //   837e1410             | cmp                 dword ptr [esi + 0x14], 0x10
            //   7204                 | jb                  6
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   eb02                 | jmp                 4
            //   8bc6                 | mov                 eax, esi

        $sequence_2 = { 50 6a00 6a00 e8???????? 8d7801 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   e8????????           |                     
            //   8d7801               | lea                 edi, dword ptr [eax + 1]

        $sequence_3 = { 8be5 5d c3 837f4c00 750a 83c8ff 5f }
            // n = 7, score = 100
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   837f4c00             | cmp                 dword ptr [edi + 0x4c], 0
            //   750a                 | jne                 0xc
            //   83c8ff               | or                  eax, 0xffffffff
            //   5f                   | pop                 edi

        $sequence_4 = { e8???????? 8b7508 c746140f000000 c7461000000000 c60600 8b5528 83fa10 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   c746140f000000       | mov                 dword ptr [esi + 0x14], 0xf
            //   c7461000000000       | mov                 dword ptr [esi + 0x10], 0
            //   c60600               | mov                 byte ptr [esi], 0
            //   8b5528               | mov                 edx, dword ptr [ebp + 0x28]
            //   83fa10               | cmp                 edx, 0x10

        $sequence_5 = { c3 c706???????? 8b06 5e 8be5 5d c3 }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   c706????????         |                     
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   5e                   | pop                 esi
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 

        $sequence_6 = { 8b30 8bd6 c1fa06 8bc6 83e03f 6bc830 8b049540354500 }
            // n = 7, score = 100
            //   8b30                 | mov                 esi, dword ptr [eax]
            //   8bd6                 | mov                 edx, esi
            //   c1fa06               | sar                 edx, 6
            //   8bc6                 | mov                 eax, esi
            //   83e03f               | and                 eax, 0x3f
            //   6bc830               | imul                ecx, eax, 0x30
            //   8b049540354500       | mov                 eax, dword ptr [edx*4 + 0x453540]

        $sequence_7 = { 56 57 6a01 8bf2 8bf9 e8???????? 83c404 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   6a01                 | push                1
            //   8bf2                 | mov                 esi, edx
            //   8bf9                 | mov                 edi, ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_8 = { c645b400 85c9 7411 8b01 ff5008 }
            // n = 5, score = 100
            //   c645b400             | mov                 byte ptr [ebp - 0x4c], 0
            //   85c9                 | test                ecx, ecx
            //   7411                 | je                  0x13
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   ff5008               | call                dword ptr [eax + 8]

        $sequence_9 = { e9???????? 8d8d78ffffff e9???????? 8d4db0 e9???????? 8d4d80 e9???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8d8d78ffffff         | lea                 ecx, dword ptr [ebp - 0x88]
            //   e9????????           |                     
            //   8d4db0               | lea                 ecx, dword ptr [ebp - 0x50]
            //   e9????????           |                     
            //   8d4d80               | lea                 ecx, dword ptr [ebp - 0x80]
            //   e9????????           |                     

    condition:
        7 of them and filesize < 753664
}