rule win_zeoticus_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.zeoticus."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zeoticus"
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
        $sequence_0 = { 836dc002 8b5dcc 0f8547feffff 8b5ddc 8b45b4 03c1 8b75c4 }
            // n = 7, score = 100
            //   836dc002             | sub                 dword ptr [ebp - 0x40], 2
            //   8b5dcc               | mov                 ebx, dword ptr [ebp - 0x34]
            //   0f8547feffff         | jne                 0xfffffe4d
            //   8b5ddc               | mov                 ebx, dword ptr [ebp - 0x24]
            //   8b45b4               | mov                 eax, dword ptr [ebp - 0x4c]
            //   03c1                 | add                 eax, ecx
            //   8b75c4               | mov                 esi, dword ptr [ebp - 0x3c]

        $sequence_1 = { 742a 68f2b57c1c 6a09 ba???????? b9cb0cf2af e8???????? 83c408 }
            // n = 7, score = 100
            //   742a                 | je                  0x2c
            //   68f2b57c1c           | push                0x1c7cb5f2
            //   6a09                 | push                9
            //   ba????????           |                     
            //   b9cb0cf2af           | mov                 ecx, 0xaff20ccb
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_2 = { 83feff 7514 57 e8???????? 83c404 56 }
            // n = 6, score = 100
            //   83feff               | cmp                 esi, -1
            //   7514                 | jne                 0x16
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   56                   | push                esi

        $sequence_3 = { 6a00 6a00 6a00 ff75f0 68???????? ffd0 f7d8 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   68????????           |                     
            //   ffd0                 | call                eax
            //   f7d8                 | neg                 eax

        $sequence_4 = { 660fd4642450 660fefd3 0f107870 660fd4e1 660f70cab1 }
            // n = 5, score = 100
            //   660fd4642450         | paddq               xmm4, xmmword ptr [esp + 0x50]
            //   660fefd3             | pxor                xmm2, xmm3
            //   0f107870             | movups              xmm7, xmmword ptr [eax + 0x70]
            //   660fd4e1             | paddq               xmm4, xmm1
            //   660f70cab1           | pshufd              xmm1, xmm2, -0x4f

        $sequence_5 = { 895c2428 8bd9 0facc118 c1e308 c1e818 0bf9 }
            // n = 6, score = 100
            //   895c2428             | mov                 dword ptr [esp + 0x28], ebx
            //   8bd9                 | mov                 ebx, ecx
            //   0facc118             | shrd                ecx, eax, 0x18
            //   c1e308               | shl                 ebx, 8
            //   c1e818               | shr                 eax, 0x18
            //   0bf9                 | or                  edi, ecx

        $sequence_6 = { 8bda c1eb1a 035c2418 8bc3 c1e81a 03c6 89442414 }
            // n = 7, score = 100
            //   8bda                 | mov                 ebx, edx
            //   c1eb1a               | shr                 ebx, 0x1a
            //   035c2418             | add                 ebx, dword ptr [esp + 0x18]
            //   8bc3                 | mov                 eax, ebx
            //   c1e81a               | shr                 eax, 0x1a
            //   03c6                 | add                 eax, esi
            //   89442414             | mov                 dword ptr [esp + 0x14], eax

        $sequence_7 = { 660f70fa55 0f29add0fdffff 0f29b5c0fdffff 0f2945a0 0f57c0 894dfc 8d4840 }
            // n = 7, score = 100
            //   660f70fa55           | pshufd              xmm7, xmm2, 0x55
            //   0f29add0fdffff       | movaps              xmmword ptr [ebp - 0x230], xmm5
            //   0f29b5c0fdffff       | movaps              xmmword ptr [ebp - 0x240], xmm6
            //   0f2945a0             | movaps              xmmword ptr [ebp - 0x60], xmm0
            //   0f57c0               | xorps               xmm0, xmm0
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8d4840               | lea                 ecx, dword ptr [eax + 0x40]

        $sequence_8 = { 33d9 8b4c243c 03cb 894c243c 13c7 334c2478 33d2 }
            // n = 7, score = 100
            //   33d9                 | xor                 ebx, ecx
            //   8b4c243c             | mov                 ecx, dword ptr [esp + 0x3c]
            //   03cb                 | add                 ecx, ebx
            //   894c243c             | mov                 dword ptr [esp + 0x3c], ecx
            //   13c7                 | adc                 eax, edi
            //   334c2478             | xor                 ecx, dword ptr [esp + 0x78]
            //   33d2                 | xor                 edx, edx

        $sequence_9 = { 660fefc8 0f1044059c 0f1149c0 0f104c0620 660fefc8 0f104405ac 0f1149d0 }
            // n = 7, score = 100
            //   660fefc8             | pxor                xmm1, xmm0
            //   0f1044059c           | movups              xmm0, xmmword ptr [ebp + eax - 0x64]
            //   0f1149c0             | movups              xmmword ptr [ecx - 0x40], xmm1
            //   0f104c0620           | movups              xmm1, xmmword ptr [esi + eax + 0x20]
            //   660fefc8             | pxor                xmm1, xmm0
            //   0f104405ac           | movups              xmm0, xmmword ptr [ebp + eax - 0x54]
            //   0f1149d0             | movups              xmmword ptr [ecx - 0x30], xmm1

    condition:
        7 of them and filesize < 468992
}