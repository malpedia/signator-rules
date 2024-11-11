rule win_bookcodesrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.bookcodesrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bookcodesrat"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
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
        $sequence_0 = { ff15???????? 4883bba036000000 48898318360000 0f847f040000 4883bba836000000 0f8471040000 4883bb1036000000 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   4883bba036000000     | inc                 ecx
            //   48898318360000       | mov                 eax, 0x104
            //   0f847f040000         | dec                 eax
            //   4883bba836000000     | lea                 ecx, [esp + 0x1c0]
            //   0f8471040000         | mov                 edx, 0x104
            //   4883bb1036000000     | dec                 eax

        $sequence_1 = { 4c8b442460 ba01000000 498bcc ffd3 488bc3 4883c440 415d }
            // n = 7, score = 100
            //   4c8b442460           | dec                 eax
            //   ba01000000           | or                  ecx, 0xffffffff
            //   498bcc               | mov                 dword ptr [edx + 4], eax
            //   ffd3                 | inc                 ecx
            //   488bc3               | mov                 eax, dword ptr [eax + 0xc]
            //   4883c440             | mov                 ecx, eax
            //   415d                 | mov                 dword ptr [edx + 8], eax

        $sequence_2 = { e8???????? 488d7b58 be06000000 488d05f5300200 483947f0 7412 488b0f }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488d7b58             | inc                 edx
            //   be06000000           | movsx               ecx, byte ptr [eax + ecx + 0x33610]
            //   488d05f5300200       | and                 ecx, 0xf
            //   483947f0             | jmp                 0x4a7
            //   7412                 | inc                 ecx
            //   488b0f               | mov                 ecx, edx

        $sequence_3 = { 498bcd e8???????? 48ffc3 e9???????? 498bcd e8???????? 48ffc3 }
            // n = 7, score = 100
            //   498bcd               | lea                 edx, [0x2017b]
            //   e8????????           |                     
            //   48ffc3               | dec                 eax
            //   e9????????           |                     
            //   498bcd               | mov                 ecx, ebx
            //   e8????????           |                     
            //   48ffc3               | test                eax, eax

        $sequence_4 = { 488bf0 ff9360370000 488d8d78040000 4c8be0 ff9360370000 488d8d48050000 4c8bf8 }
            // n = 7, score = 100
            //   488bf0               | dec                 esp
            //   ff9360370000         | lea                 eax, [ebp - 0x60]
            //   488d8d78040000       | dec                 eax
            //   4c8be0               | mov                 edx, edi
            //   ff9360370000         | dec                 eax
            //   488d8d48050000       | lea                 ecx, [esp + 0x40]
            //   4c8bf8               | test                eax, eax

        $sequence_5 = { 888548070000 48898549070000 48898551070000 888588060000 48898589060000 48898591060000 898599060000 }
            // n = 7, score = 100
            //   888548070000         | jne                 0xc01
            //   48898549070000       | call                dword ptr [ebx + 0x3670]
            //   48898551070000       | dec                 eax
            //   888588060000         | mov                 ecx, dword ptr [ebx + 0x420]
            //   48898589060000       | call                dword ptr [ebx + 0x3670]
            //   48898591060000       | dec                 eax
            //   898599060000         | mov                 dword ptr [esp + 0x50], edi

        $sequence_6 = { 488bcf 48898350370000 ff15???????? 488d9520040000 488bcf 48898358370000 }
            // n = 6, score = 100
            //   488bcf               | dec                 eax
            //   48898350370000       | lea                 ecx, [esi + 0x3330]
            //   ff15????????         |                     
            //   488d9520040000       | mov                 ecx, 0x3a98
            //   488bcf               | test                eax, eax
            //   48898358370000       | je                  0x1743

        $sequence_7 = { 8bc3 488b8c24d0020000 4833cc e8???????? 4881c4e0020000 }
            // n = 5, score = 100
            //   8bc3                 | mov                 dword ptr [ebp - 0x68], 0x475d5a60
            //   488b8c24d0020000     | mov                 dword ptr [ebp - 0x64], 0x1a5c4656
            //   4833cc               | mov                 word ptr [ebp - 0x60], 0x565f
            //   e8????????           |                     
            //   4881c4e0020000       | dec                 eax

        $sequence_8 = { 4c897c2420 4c8d05e46dffff 0f1f4000 4885db 7504 }
            // n = 5, score = 100
            //   4c897c2420           | dec                 eax
            //   4c8d05e46dffff       | mov                 dword ptr [esp + 0x20], eax
            //   0f1f4000             | inc                 esp
            //   4885db               | lea                 ecx, [edi + 4]
            //   7504                 | dec                 esp

        $sequence_9 = { 48ffc6 4883c310 493bf4 b900000000 7c8e 4c8b6580 4c8b6c2478 }
            // n = 7, score = 100
            //   48ffc6               | push                ebx
            //   4883c310             | dec                 eax
            //   493bf4               | sub                 esp, 0x250
            //   b900000000           | dec                 eax
            //   7c8e                 | xor                 eax, esp
            //   4c8b6580             | cmp                 edx, 0x7fff
            //   4c8b6c2478           | sete                dl

    condition:
        7 of them and filesize < 544768
}