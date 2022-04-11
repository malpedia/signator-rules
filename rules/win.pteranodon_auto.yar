rule win_pteranodon_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.pteranodon."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pteranodon"
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
        $sequence_0 = { 8855d4 8b0485b8690310 88540828 8b0b 8bc1 }
            // n = 5, score = 100
            //   8855d4               | mov                 byte ptr [ebp - 0x2c], dl
            //   8b0485b8690310       | mov                 eax, dword ptr [eax*4 + 0x100369b8]
            //   88540828             | mov                 byte ptr [eax + ecx + 0x28], dl
            //   8b0b                 | mov                 ecx, dword ptr [ebx]
            //   8bc1                 | mov                 eax, ecx

        $sequence_1 = { 40 8d8dd8feffff 50 ffb5d8feffff e8???????? 56 8d8dd8feffff }
            // n = 7, score = 100
            //   40                   | inc                 eax
            //   8d8dd8feffff         | lea                 ecx, dword ptr [ebp - 0x128]
            //   50                   | push                eax
            //   ffb5d8feffff         | push                dword ptr [ebp - 0x128]
            //   e8????????           |                     
            //   56                   | push                esi
            //   8d8dd8feffff         | lea                 ecx, dword ptr [ebp - 0x128]

        $sequence_2 = { 7213 40 8d8d90feffff 50 ffb590feffff }
            // n = 5, score = 100
            //   7213                 | jb                  0x15
            //   40                   | inc                 eax
            //   8d8d90feffff         | lea                 ecx, dword ptr [ebp - 0x170]
            //   50                   | push                eax
            //   ffb590feffff         | push                dword ptr [ebp - 0x170]

        $sequence_3 = { 84c9 75f3 8d55f0 8bf2 8a02 42 84c0 }
            // n = 7, score = 100
            //   84c9                 | test                cl, cl
            //   75f3                 | jne                 0xfffffff5
            //   8d55f0               | lea                 edx, dword ptr [ebp - 0x10]
            //   8bf2                 | mov                 esi, edx
            //   8a02                 | mov                 al, byte ptr [edx]
            //   42                   | inc                 edx
            //   84c0                 | test                al, al

        $sequence_4 = { 74e9 8a0e 0fb6c1 0fbe80205a0310 85c0 }
            // n = 5, score = 100
            //   74e9                 | je                  0xffffffeb
            //   8a0e                 | mov                 cl, byte ptr [esi]
            //   0fb6c1               | movzx               eax, cl
            //   0fbe80205a0310       | movsx               eax, byte ptr [eax + 0x10035a20]
            //   85c0                 | test                eax, eax

        $sequence_5 = { c6060d 8b048db8690310 8854382a eb2e 807dff0a 750d 8b550c }
            // n = 7, score = 100
            //   c6060d               | mov                 byte ptr [esi], 0xd
            //   8b048db8690310       | mov                 eax, dword ptr [ecx*4 + 0x100369b8]
            //   8854382a             | mov                 byte ptr [eax + edi + 0x2a], dl
            //   eb2e                 | jmp                 0x30
            //   807dff0a             | cmp                 byte ptr [ebp - 1], 0xa
            //   750d                 | jne                 0xf
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]

        $sequence_6 = { 8d8dd4f5ffff e8???????? 6a00 56 57 ffb5a0f6ffff }
            // n = 6, score = 100
            //   8d8dd4f5ffff         | lea                 ecx, dword ptr [ebp - 0xa2c]
            //   e8????????           |                     
            //   6a00                 | push                0
            //   56                   | push                esi
            //   57                   | push                edi
            //   ffb5a0f6ffff         | push                dword ptr [ebp - 0x960]

        $sequence_7 = { eb02 33ff 8d95b8faffff e8???????? 83f8ff 7513 33c0 }
            // n = 7, score = 100
            //   eb02                 | jmp                 4
            //   33ff                 | xor                 edi, edi
            //   8d95b8faffff         | lea                 edx, dword ptr [ebp - 0x548]
            //   e8????????           |                     
            //   83f8ff               | cmp                 eax, -1
            //   7513                 | jne                 0x15
            //   33c0                 | xor                 eax, eax

        $sequence_8 = { 8d8df0f8ffff e8???????? 8d8da8f8ffff c645fc2b 51 8bd0 }
            // n = 6, score = 100
            //   8d8df0f8ffff         | lea                 ecx, dword ptr [ebp - 0x710]
            //   e8????????           |                     
            //   8d8da8f8ffff         | lea                 ecx, dword ptr [ebp - 0x758]
            //   c645fc2b             | mov                 byte ptr [ebp - 4], 0x2b
            //   51                   | push                ecx
            //   8bd0                 | mov                 edx, eax

        $sequence_9 = { 8d8d78ffffff c745fc01000000 e8???????? 8bf0 8d4d90 }
            // n = 5, score = 100
            //   8d8d78ffffff         | lea                 ecx, dword ptr [ebp - 0x88]
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   8d4d90               | lea                 ecx, dword ptr [ebp - 0x70]

    condition:
        7 of them and filesize < 499712
}