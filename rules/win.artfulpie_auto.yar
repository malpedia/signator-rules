rule win_artfulpie_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.artfulpie."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.artfulpie"
        malpedia_rule_date = "20221118"
        malpedia_hash = "e0702e2e6d1d00da65c8a29a4ebacd0a4c59e1af"
        malpedia_version = "20221125"
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
        $sequence_0 = { 5e 8be5 5d c3 8b35???????? 57 ffd6 }
            // n = 7, score = 100
            //   5e                   | pop                 esi
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b35????????         |                     
            //   57                   | push                edi
            //   ffd6                 | call                esi

        $sequence_1 = { c745e400000000 c745f801000000 663b4706 0f83a0000000 83c364 8b7630 }
            // n = 6, score = 100
            //   c745e400000000       | mov                 dword ptr [ebp - 0x1c], 0
            //   c745f801000000       | mov                 dword ptr [ebp - 8], 1
            //   663b4706             | cmp                 ax, word ptr [edi + 6]
            //   0f83a0000000         | jae                 0xa6
            //   83c364               | add                 ebx, 0x64
            //   8b7630               | mov                 esi, dword ptr [esi + 0x30]

        $sequence_2 = { 03fb 50 57 e8???????? 897ef8 8b15???????? }
            // n = 6, score = 100
            //   03fb                 | add                 edi, ebx
            //   50                   | push                eax
            //   57                   | push                edi
            //   e8????????           |                     
            //   897ef8               | mov                 dword ptr [esi - 8], edi
            //   8b15????????         |                     

        $sequence_3 = { 8b5034 2b5634 740c 8bcb }
            // n = 4, score = 100
            //   8b5034               | mov                 edx, dword ptr [eax + 0x34]
            //   2b5634               | sub                 edx, dword ptr [esi + 0x34]
            //   740c                 | je                  0xe
            //   8bcb                 | mov                 ecx, ebx

        $sequence_4 = { 660f1f440000 8d1c31 ff7728 85c0 7905 }
            // n = 5, score = 100
            //   660f1f440000         | nop                 word ptr [eax + eax]
            //   8d1c31               | lea                 ebx, [ecx + esi]
            //   ff7728               | push                dword ptr [edi + 0x28]
            //   85c0                 | test                eax, eax
            //   7905                 | jns                 7

        $sequence_5 = { 0f118558ffffff 56 0f2805???????? 8bf1 0f118568ffffff }
            // n = 5, score = 100
            //   0f118558ffffff       | movups              xmmword ptr [ebp - 0xa8], xmm0
            //   56                   | push                esi
            //   0f2805????????       |                     
            //   8bf1                 | mov                 esi, ecx
            //   0f118568ffffff       | movups              xmmword ptr [ebp - 0x98], xmm0

        $sequence_6 = { 8901 33c0 40 e9???????? 8365c800 c745cc6b464000 a1???????? }
            // n = 7, score = 100
            //   8901                 | mov                 dword ptr [ecx], eax
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax
            //   e9????????           |                     
            //   8365c800             | and                 dword ptr [ebp - 0x38], 0
            //   c745cc6b464000       | mov                 dword ptr [ebp - 0x34], 0x40466b
            //   a1????????           |                     

        $sequence_7 = { 8b5d0c 56 33f6 83fb40 }
            // n = 4, score = 100
            //   8b5d0c               | mov                 ebx, dword ptr [ebp + 0xc]
            //   56                   | push                esi
            //   33f6                 | xor                 esi, esi
            //   83fb40               | cmp                 ebx, 0x40

        $sequence_8 = { 75e3 8d45d4 50 ff15???????? 8b4dd8 8d51ff 8d59ff }
            // n = 7, score = 100
            //   75e3                 | jne                 0xffffffe5
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b4dd8               | mov                 ecx, dword ptr [ebp - 0x28]
            //   8d51ff               | lea                 edx, [ecx - 1]
            //   8d59ff               | lea                 ebx, [ecx - 1]

        $sequence_9 = { e8???????? 83c414 85c0 7465 8b03 8b5034 2b5634 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   85c0                 | test                eax, eax
            //   7465                 | je                  0x67
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   8b5034               | mov                 edx, dword ptr [eax + 0x34]
            //   2b5634               | sub                 edx, dword ptr [esi + 0x34]

    condition:
        7 of them and filesize < 204800
}