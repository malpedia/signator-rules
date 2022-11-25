rule win_redpepper_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.redpepper."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redpepper"
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
        $sequence_0 = { 7526 833e02 7509 5f 5e b806000000 5d }
            // n = 7, score = 300
            //   7526                 | jne                 0x28
            //   833e02               | cmp                 dword ptr [esi], 2
            //   7509                 | jne                 0xb
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   b806000000           | mov                 eax, 6
            //   5d                   | pop                 ebp

        $sequence_1 = { 8b44242c 83c410 85c0 7412 8b542414 }
            // n = 5, score = 300
            //   8b44242c             | mov                 eax, dword ptr [esp + 0x2c]
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax
            //   7412                 | je                  0x14
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]

        $sequence_2 = { 8d440202 89442410 eb37 8d4c242c 89442420 51 }
            // n = 6, score = 300
            //   8d440202             | lea                 eax, [edx + eax + 2]
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   eb37                 | jmp                 0x39
            //   8d4c242c             | lea                 ecx, [esp + 0x2c]
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   51                   | push                ecx

        $sequence_3 = { f7f9 83c241 5f 8ac2 5e c9 c3 }
            // n = 7, score = 300
            //   f7f9                 | idiv                ecx
            //   83c241               | add                 edx, 0x41
            //   5f                   | pop                 edi
            //   8ac2                 | mov                 al, dl
            //   5e                   | pop                 esi
            //   c9                   | leave               
            //   c3                   | ret                 

        $sequence_4 = { 40 c1fa08 8808 885001 885802 8b463c 83c304 }
            // n = 7, score = 300
            //   40                   | inc                 eax
            //   c1fa08               | sar                 edx, 8
            //   8808                 | mov                 byte ptr [eax], cl
            //   885001               | mov                 byte ptr [eax + 1], dl
            //   885802               | mov                 byte ptr [eax + 2], bl
            //   8b463c               | mov                 eax, dword ptr [esi + 0x3c]
            //   83c304               | add                 ebx, 4

        $sequence_5 = { 03c8 885500 894c2410 8b6c2418 8b44241c }
            // n = 5, score = 300
            //   03c8                 | add                 ecx, eax
            //   885500               | mov                 byte ptr [ebp], dl
            //   894c2410             | mov                 dword ptr [esp + 0x10], ecx
            //   8b6c2418             | mov                 ebp, dword ptr [esp + 0x18]
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]

        $sequence_6 = { 7c11 80f95a 7f0c 0fbec9 }
            // n = 4, score = 300
            //   7c11                 | jl                  0x13
            //   80f95a               | cmp                 cl, 0x5a
            //   7f0c                 | jg                  0xe
            //   0fbec9               | movsx               ecx, cl

        $sequence_7 = { e8???????? 50 57 e8???????? 55 e8???????? }
            // n = 6, score = 300
            //   e8????????           |                     
            //   50                   | push                eax
            //   57                   | push                edi
            //   e8????????           |                     
            //   55                   | push                ebp
            //   e8????????           |                     

        $sequence_8 = { c744241400000000 7282 8b742410 56 e8???????? 83c404 85c0 }
            // n = 7, score = 300
            //   c744241400000000     | mov                 dword ptr [esp + 0x14], 0
            //   7282                 | jb                  0xffffff84
            //   8b742410             | mov                 esi, dword ptr [esp + 0x10]
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax

        $sequence_9 = { 8d6c2e03 3beb 0f878e000000 89442420 8d442428 }
            // n = 5, score = 300
            //   8d6c2e03             | lea                 ebp, [esi + ebp + 3]
            //   3beb                 | cmp                 ebp, ebx
            //   0f878e000000         | ja                  0x94
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   8d442428             | lea                 eax, [esp + 0x28]

    condition:
        7 of them and filesize < 2482176
}