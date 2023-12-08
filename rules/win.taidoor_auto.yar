rule win_taidoor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.taidoor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.taidoor"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
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
        $sequence_0 = { 7cf5 c745fcfcffffff 33ff 33db }
            // n = 4, score = 300
            //   7cf5                 | jl                  0xfffffff7
            //   c745fcfcffffff       | mov                 dword ptr [ebp - 4], 0xfffffffc
            //   33ff                 | xor                 edi, edi
            //   33db                 | xor                 ebx, ebx

        $sequence_1 = { f775fc 8bf2 8d04f6 ffb485f4b7ffff ff15???????? 85c0 }
            // n = 6, score = 300
            //   f775fc               | div                 dword ptr [ebp - 4]
            //   8bf2                 | mov                 esi, edx
            //   8d04f6               | lea                 eax, [esi + esi*8]
            //   ffb485f4b7ffff       | push                dword ptr [ebp + eax*4 - 0x480c]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_2 = { 59 8d85a0fdffff 59 50 e8???????? }
            // n = 5, score = 300
            //   59                   | pop                 ecx
            //   8d85a0fdffff         | lea                 eax, [ebp - 0x260]
            //   59                   | pop                 ecx
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_3 = { 57 a0???????? c745fc01000000 8ac8 f6d9 1bc9 33db }
            // n = 7, score = 300
            //   57                   | push                edi
            //   a0????????           |                     
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   8ac8                 | mov                 cl, al
            //   f6d9                 | neg                 cl
            //   1bc9                 | sbb                 ecx, ecx
            //   33db                 | xor                 ebx, ebx

        $sequence_4 = { 66ab aa 895dfc ffd6 40 85c0 7e29 }
            // n = 7, score = 300
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   ffd6                 | call                esi
            //   40                   | inc                 eax
            //   85c0                 | test                eax, eax
            //   7e29                 | jle                 0x2b

        $sequence_5 = { b940420f00 f7f9 8d45e0 52 ff35???????? ff35???????? }
            // n = 6, score = 300
            //   b940420f00           | mov                 ecx, 0xf4240
            //   f7f9                 | idiv                ecx
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   52                   | push                edx
            //   ff35????????         |                     
            //   ff35????????         |                     

        $sequence_6 = { ff75f0 ffd6 8d4d08 885dfc e8???????? 834dfcff 8d4d10 }
            // n = 7, score = 300
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   ffd6                 | call                esi
            //   8d4d08               | lea                 ecx, [ebp + 8]
            //   885dfc               | mov                 byte ptr [ebp - 4], bl
            //   e8????????           |                     
            //   834dfcff             | or                  dword ptr [ebp - 4], 0xffffffff
            //   8d4d10               | lea                 ecx, [ebp + 0x10]

        $sequence_7 = { ff75ec 8d4df0 e8???????? 8b450c 46 3b70f8 7cdc }
            // n = 7, score = 300
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   8d4df0               | lea                 ecx, [ebp - 0x10]
            //   e8????????           |                     
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   46                   | inc                 esi
            //   3b70f8               | cmp                 esi, dword ptr [eax - 8]
            //   7cdc                 | jl                  0xffffffde

        $sequence_8 = { e8???????? ff75ec 8d85a0fdffff 50 51 8bcc 8965f4 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   8d85a0fdffff         | lea                 eax, [ebp - 0x260]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   8bcc                 | mov                 ecx, esp
            //   8965f4               | mov                 dword ptr [ebp - 0xc], esp

        $sequence_9 = { bf80020000 57 c745fc01000000 ffd3 8bf0 }
            // n = 5, score = 300
            //   bf80020000           | mov                 edi, 0x280
            //   57                   | push                edi
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   ffd3                 | call                ebx
            //   8bf0                 | mov                 esi, eax

    condition:
        7 of them and filesize < 49152
}