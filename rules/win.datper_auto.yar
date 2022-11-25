rule win_datper_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.datper."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.datper"
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
        $sequence_0 = { 8d95bcf7ffff 33c0 e8???????? ffb5bcf7ffff 68???????? 8d85c0f7ffff ba03000000 }
            // n = 7, score = 200
            //   8d95bcf7ffff         | lea                 edx, [ebp - 0x844]
            //   33c0                 | xor                 eax, eax
            //   e8????????           |                     
            //   ffb5bcf7ffff         | push                dword ptr [ebp - 0x844]
            //   68????????           |                     
            //   8d85c0f7ffff         | lea                 eax, [ebp - 0x840]
            //   ba03000000           | mov                 edx, 3

        $sequence_1 = { 8b55f4 e8???????? 8b55d0 b901000000 b8???????? }
            // n = 5, score = 200
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   8b55d0               | mov                 edx, dword ptr [ebp - 0x30]
            //   b901000000           | mov                 ecx, 1
            //   b8????????           |                     

        $sequence_2 = { e8???????? c78588feffff05000000 33c0 89858cfeffff 8b55d0 8b45d4 33c9 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   c78588feffff05000000     | mov    dword ptr [ebp - 0x178], 5
            //   33c0                 | xor                 eax, eax
            //   89858cfeffff         | mov                 dword ptr [ebp - 0x174], eax
            //   8b55d0               | mov                 edx, dword ptr [ebp - 0x30]
            //   8b45d4               | mov                 eax, dword ptr [ebp - 0x2c]
            //   33c9                 | xor                 ecx, ecx

        $sequence_3 = { 8bc6 48 740c 48 7521 6a00 e8???????? }
            // n = 7, score = 200
            //   8bc6                 | mov                 eax, esi
            //   48                   | dec                 eax
            //   740c                 | je                  0xe
            //   48                   | dec                 eax
            //   7521                 | jne                 0x23
            //   6a00                 | push                0
            //   e8????????           |                     

        $sequence_4 = { 8b55f0 0fb64de2 c1e106 0fb65de3 0acb 884c1001 }
            // n = 6, score = 200
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   0fb64de2             | movzx               ecx, byte ptr [ebp - 0x1e]
            //   c1e106               | shl                 ecx, 6
            //   0fb65de3             | movzx               ebx, byte ptr [ebp - 0x1d]
            //   0acb                 | or                  cl, bl
            //   884c1001             | mov                 byte ptr [eax + edx + 1], cl

        $sequence_5 = { 8b09 8bd3 8bc3 e8???????? }
            // n = 4, score = 200
            //   8b09                 | mov                 ecx, dword ptr [ecx]
            //   8bd3                 | mov                 edx, ebx
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     

        $sequence_6 = { 50 e8???????? 50 56 8b4df0 33d2 }
            // n = 6, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   50                   | push                eax
            //   56                   | push                esi
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   33d2                 | xor                 edx, edx

        $sequence_7 = { 740c 48 7521 6a00 }
            // n = 4, score = 200
            //   740c                 | je                  0xe
            //   48                   | dec                 eax
            //   7521                 | jne                 0x23
            //   6a00                 | push                0

        $sequence_8 = { e8???????? 6a00 8d4598 50 8b459c 50 8b45ec }
            // n = 7, score = 200
            //   e8????????           |                     
            //   6a00                 | push                0
            //   8d4598               | lea                 eax, [ebp - 0x68]
            //   50                   | push                eax
            //   8b459c               | mov                 eax, dword ptr [ebp - 0x64]
            //   50                   | push                eax
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]

        $sequence_9 = { 0f8cbe000000 33c0 8945ec bb01000000 e9???????? 8b75f8 85f6 }
            // n = 7, score = 200
            //   0f8cbe000000         | jl                  0xc4
            //   33c0                 | xor                 eax, eax
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   bb01000000           | mov                 ebx, 1
            //   e9????????           |                     
            //   8b75f8               | mov                 esi, dword ptr [ebp - 8]
            //   85f6                 | test                esi, esi

    condition:
        7 of them and filesize < 253952
}