rule win_jasus_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.jasus."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.jasus"
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
        $sequence_0 = { 50 53 51 e9???????? 8d75f8 e8???????? 84c0 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   53                   | push                ebx
            //   51                   | push                ecx
            //   e9????????           |                     
            //   8d75f8               | lea                 esi, [ebp - 8]
            //   e8????????           |                     
            //   84c0                 | test                al, al

        $sequence_1 = { 83c40c 84c0 742f 8b45f8 668b4dfc 897306 668b15???????? }
            // n = 7, score = 200
            //   83c40c               | add                 esp, 0xc
            //   84c0                 | test                al, al
            //   742f                 | je                  0x31
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   668b4dfc             | mov                 cx, word ptr [ebp - 4]
            //   897306               | mov                 dword ptr [ebx + 6], esi
            //   668b15????????       |                     

        $sequence_2 = { e8???????? 83c408 895e24 891e eb14 3bc8 7503 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   895e24               | mov                 dword ptr [esi + 0x24], ebx
            //   891e                 | mov                 dword ptr [esi], ebx
            //   eb14                 | jmp                 0x16
            //   3bc8                 | cmp                 ecx, eax
            //   7503                 | jne                 5

        $sequence_3 = { 8b45fc 894b20 c7432401000000 894318 c7431c00000000 85c0 }
            // n = 6, score = 200
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   894b20               | mov                 dword ptr [ebx + 0x20], ecx
            //   c7432401000000       | mov                 dword ptr [ebx + 0x24], 1
            //   894318               | mov                 dword ptr [ebx + 0x18], eax
            //   c7431c00000000       | mov                 dword ptr [ebx + 0x1c], 0
            //   85c0                 | test                eax, eax

        $sequence_4 = { 33f8 81e7ff000000 c1e808 3304bda0ca4100 0fb67902 }
            // n = 5, score = 200
            //   33f8                 | xor                 edi, eax
            //   81e7ff000000         | and                 edi, 0xff
            //   c1e808               | shr                 eax, 8
            //   3304bda0ca4100       | xor                 eax, dword ptr [edi*4 + 0x41caa0]
            //   0fb67902             | movzx               edi, byte ptr [ecx + 2]

        $sequence_5 = { 0f95c0 fec8 24fb 043f 5e }
            // n = 5, score = 200
            //   0f95c0               | setne               al
            //   fec8                 | dec                 al
            //   24fb                 | and                 al, 0xfb
            //   043f                 | add                 al, 0x3f
            //   5e                   | pop                 esi

        $sequence_6 = { 8b06 8bc8 83e01f c1f905 8b0c8d809d4300 c1e006 8d440104 }
            // n = 7, score = 200
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8bc8                 | mov                 ecx, eax
            //   83e01f               | and                 eax, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   8b0c8d809d4300       | mov                 ecx, dword ptr [ecx*4 + 0x439d80]
            //   c1e006               | shl                 eax, 6
            //   8d440104             | lea                 eax, [ecx + eax + 4]

        $sequence_7 = { 89458a 66894d8e 8955a0 89459a 66894d9e ffd6 8b8d64feffff }
            // n = 7, score = 200
            //   89458a               | mov                 dword ptr [ebp - 0x76], eax
            //   66894d8e             | mov                 word ptr [ebp - 0x72], cx
            //   8955a0               | mov                 dword ptr [ebp - 0x60], edx
            //   89459a               | mov                 dword ptr [ebp - 0x66], eax
            //   66894d9e             | mov                 word ptr [ebp - 0x62], cx
            //   ffd6                 | call                esi
            //   8b8d64feffff         | mov                 ecx, dword ptr [ebp - 0x19c]

        $sequence_8 = { 3bc1 743f 85c0 0f84b7000000 85c9 0f84af000000 8bff }
            // n = 7, score = 200
            //   3bc1                 | cmp                 eax, ecx
            //   743f                 | je                  0x41
            //   85c0                 | test                eax, eax
            //   0f84b7000000         | je                  0xbd
            //   85c9                 | test                ecx, ecx
            //   0f84af000000         | je                  0xb5
            //   8bff                 | mov                 edi, edi

        $sequence_9 = { 0f8723020000 663915???????? 0f8716020000 663915???????? 0f8709020000 663915???????? 0f87fc010000 }
            // n = 7, score = 200
            //   0f8723020000         | ja                  0x229
            //   663915????????       |                     
            //   0f8716020000         | ja                  0x21c
            //   663915????????       |                     
            //   0f8709020000         | ja                  0x20f
            //   663915????????       |                     
            //   0f87fc010000         | ja                  0x202

    condition:
        7 of them and filesize < 507904
}