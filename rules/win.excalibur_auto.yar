rule win_excalibur_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.excalibur."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.excalibur"
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
        $sequence_0 = { 8d3409 0fb7141e 81ff00000001 7314 8b4dfc c1e008 0fb609 }
            // n = 7, score = 100
            //   8d3409               | lea                 esi, dword ptr [ecx + ecx]
            //   0fb7141e             | movzx               edx, word ptr [esi + ebx]
            //   81ff00000001         | cmp                 edi, 0x1000000
            //   7314                 | jae                 0x16
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   c1e008               | shl                 eax, 8
            //   0fb609               | movzx               ecx, byte ptr [ecx]

        $sequence_1 = { 0f8492010000 837d1000 0f84af010000 85c0 0f8592010000 c745f801000000 837e5000 }
            // n = 7, score = 100
            //   0f8492010000         | je                  0x198
            //   837d1000             | cmp                 dword ptr [ebp + 0x10], 0
            //   0f84af010000         | je                  0x1b5
            //   85c0                 | test                eax, eax
            //   0f8592010000         | jne                 0x198
            //   c745f801000000       | mov                 dword ptr [ebp - 8], 1
            //   837e5000             | cmp                 dword ptr [esi + 0x50], 0

        $sequence_2 = { 47 42 83ff14 72ee 8955f0 897e58 }
            // n = 6, score = 100
            //   47                   | inc                 edi
            //   42                   | inc                 edx
            //   83ff14               | cmp                 edi, 0x14
            //   72ee                 | jb                  0xfffffff0
            //   8955f0               | mov                 dword ptr [ebp - 0x10], edx
            //   897e58               | mov                 dword ptr [esi + 0x58], edi

        $sequence_3 = { 8b7508 8b4710 c745cc00000000 8945d0 85c0 7512 c7461407000000 }
            // n = 7, score = 100
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   8b4710               | mov                 eax, dword ptr [edi + 0x10]
            //   c745cc00000000       | mov                 dword ptr [ebp - 0x34], 0
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax
            //   85c0                 | test                eax, eax
            //   7512                 | jne                 0x14
            //   c7461407000000       | mov                 dword ptr [esi + 0x14], 7

        $sequence_4 = { 740a 6aff 6a00 50 e8???????? 6a0d 33c0 }
            // n = 7, score = 100
            //   740a                 | je                  0xc
            //   6aff                 | push                -1
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     
            //   6a0d                 | push                0xd
            //   33c0                 | xor                 eax, eax

        $sequence_5 = { 660f62d9 660ffee3 8d4060 3bf1 72ce 660f6fc4 660f73d808 }
            // n = 7, score = 100
            //   660f62d9             | punpckldq           xmm3, xmm1
            //   660ffee3             | paddd               xmm4, xmm3
            //   8d4060               | lea                 eax, dword ptr [eax + 0x60]
            //   3bf1                 | cmp                 esi, ecx
            //   72ce                 | jb                  0xffffffd0
            //   660f6fc4             | movdqa              xmm0, xmm4
            //   660f73d808           | psrldq              xmm0, 8

        $sequence_6 = { 83c404 8bbd64fbffff 8bb558fbffff 56 e8???????? 47 83c404 }
            // n = 7, score = 100
            //   83c404               | add                 esp, 4
            //   8bbd64fbffff         | mov                 edi, dword ptr [ebp - 0x49c]
            //   8bb558fbffff         | mov                 esi, dword ptr [ebp - 0x4a8]
            //   56                   | push                esi
            //   e8????????           |                     
            //   47                   | inc                 edi
            //   83c404               | add                 esp, 4

        $sequence_7 = { 898570ffffff c7459000000000 c7458c00000000 e8???????? 83c408 85c0 0f853d010000 }
            // n = 7, score = 100
            //   898570ffffff         | mov                 dword ptr [ebp - 0x90], eax
            //   c7459000000000       | mov                 dword ptr [ebp - 0x70], 0
            //   c7458c00000000       | mov                 dword ptr [ebp - 0x74], 0
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   0f853d010000         | jne                 0x143

        $sequence_8 = { 33c0 8bbdbcfdffff 0fbebcc7f84e4300 8bc7 c1f804 }
            // n = 5, score = 100
            //   33c0                 | xor                 eax, eax
            //   8bbdbcfdffff         | mov                 edi, dword ptr [ebp - 0x244]
            //   0fbebcc7f84e4300     | movsx               edi, byte ptr [edi + eax*8 + 0x434ef8]
            //   8bc7                 | mov                 eax, edi
            //   c1f804               | sar                 eax, 4

        $sequence_9 = { c745fc01000000 8b35???????? 85db 7403 53 ffd6 }
            // n = 6, score = 100
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   8b35????????         |                     
            //   85db                 | test                ebx, ebx
            //   7403                 | je                  5
            //   53                   | push                ebx
            //   ffd6                 | call                esi

    condition:
        7 of them and filesize < 1253376
}