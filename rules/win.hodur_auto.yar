rule win_hodur_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.hodur."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hodur"
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
        $sequence_0 = { c60647 89c1 80c107 308c04d6000000 40 75f1 8db424c4000000 }
            // n = 7, score = 100
            //   c60647               | mov                 byte ptr [esi], 0x47
            //   89c1                 | mov                 ecx, eax
            //   80c107               | add                 cl, 7
            //   308c04d6000000       | xor                 byte ptr [esp + eax + 0xd6], cl
            //   40                   | inc                 eax
            //   75f1                 | jne                 0xfffffff3
            //   8db424c4000000       | lea                 esi, [esp + 0xc4]

        $sequence_1 = { 7c70 a1???????? 8d48ff 0fafc8 83e101 7460 ff75e4 }
            // n = 7, score = 100
            //   7c70                 | jl                  0x72
            //   a1????????           |                     
            //   8d48ff               | lea                 ecx, [eax - 1]
            //   0fafc8               | imul                ecx, eax
            //   83e101               | and                 ecx, 1
            //   7460                 | je                  0x62
            //   ff75e4               | push                dword ptr [ebp - 0x1c]

        $sequence_2 = { ff75ec ffd0 8b4df0 e8???????? 89f9 e8???????? 31c0 }
            // n = 7, score = 100
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   ffd0                 | call                eax
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   e8????????           |                     
            //   89f9                 | mov                 ecx, edi
            //   e8????????           |                     
            //   31c0                 | xor                 eax, eax

        $sequence_3 = { c7460428381836 c746080c043500 7c12 a1???????? 8d48ff 0fafc8 83e101 }
            // n = 7, score = 100
            //   c7460428381836       | mov                 dword ptr [esi + 4], 0x36183828
            //   c746080c043500       | mov                 dword ptr [esi + 8], 0x35040c
            //   7c12                 | jl                  0x14
            //   a1????????           |                     
            //   8d48ff               | lea                 ecx, [eax - 1]
            //   0fafc8               | imul                ecx, eax
            //   83e101               | and                 ecx, 1

        $sequence_4 = { ffb42474040000 ffd0 83f8ff 741f 833d????????0a 7c20 a1???????? }
            // n = 7, score = 100
            //   ffb42474040000       | push                dword ptr [esp + 0x474]
            //   ffd0                 | call                eax
            //   83f8ff               | cmp                 eax, -1
            //   741f                 | je                  0x21
            //   833d????????0a       |                     
            //   7c20                 | jl                  0x22
            //   a1????????           |                     

        $sequence_5 = { ffd0 c7430271706600 66c703537f 89d9 660f6e4301 660f60c0 660f61c0 }
            // n = 7, score = 100
            //   ffd0                 | call                eax
            //   c7430271706600       | mov                 dword ptr [ebx + 2], 0x667071
            //   66c703537f           | mov                 word ptr [ebx], 0x7f53
            //   89d9                 | mov                 ecx, ebx
            //   660f6e4301           | movd                xmm0, dword ptr [ebx + 1]
            //   660f60c0             | punpcklbw           xmm0, xmm0
            //   660f61c0             | punpcklwd           xmm0, xmm0

        $sequence_6 = { eb25 8d4a60 88e3 88cc 30dc 84c0 88a4148c000000 }
            // n = 7, score = 100
            //   eb25                 | jmp                 0x27
            //   8d4a60               | lea                 ecx, [edx + 0x60]
            //   88e3                 | mov                 bl, ah
            //   88cc                 | mov                 ah, cl
            //   30dc                 | xor                 ah, bl
            //   84c0                 | test                al, al
            //   88a4148c000000       | mov                 byte ptr [esp + edx + 0x8c], ah

        $sequence_7 = { e8???????? 833d????????0a 7c1a 8b0d???????? 8d51ff 0fafd1 83e201 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   833d????????0a       |                     
            //   7c1a                 | jl                  0x1c
            //   8b0d????????         |                     
            //   8d51ff               | lea                 edx, [ecx - 1]
            //   0fafd1               | imul                edx, ecx
            //   83e201               | and                 edx, 1

        $sequence_8 = { e9???????? 55 53 57 56 a1???????? 8b2d???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   55                   | push                ebp
            //   53                   | push                ebx
            //   57                   | push                edi
            //   56                   | push                esi
            //   a1????????           |                     
            //   8b2d????????         |                     

        $sequence_9 = { 81ec30010000 b8f4ffffff c7442406b792a0b4 c744240ab4a1a6a4 c744240e8eb49a00 c7042400000000 c74424141c010000 }
            // n = 7, score = 100
            //   81ec30010000         | sub                 esp, 0x130
            //   b8f4ffffff           | mov                 eax, 0xfffffff4
            //   c7442406b792a0b4     | mov                 dword ptr [esp + 6], 0xb4a092b7
            //   c744240ab4a1a6a4     | mov                 dword ptr [esp + 0xa], 0xa4a6a1b4
            //   c744240e8eb49a00     | mov                 dword ptr [esp + 0xe], 0x9ab48e
            //   c7042400000000       | mov                 dword ptr [esp], 0
            //   c74424141c010000     | mov                 dword ptr [esp + 0x14], 0x11c

    condition:
        7 of them and filesize < 1067008
}