rule win_seasalt_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.seasalt."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.seasalt"
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
        $sequence_0 = { 7515 8d4dd0 68???????? 51 }
            // n = 4, score = 100
            //   7515                 | jne                 0x17
            //   8d4dd0               | lea                 ecx, [ebp - 0x30]
            //   68????????           |                     
            //   51                   | push                ecx

        $sequence_1 = { 8b15???????? 6a00 8d8c2474010000 6804020000 51 52 ff15???????? }
            // n = 7, score = 100
            //   8b15????????         |                     
            //   6a00                 | push                0
            //   8d8c2474010000       | lea                 ecx, [esp + 0x174]
            //   6804020000           | push                0x204
            //   51                   | push                ecx
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_2 = { 7765 ff2485f4130010 8b0d???????? 68???????? 51 }
            // n = 5, score = 100
            //   7765                 | ja                  0x67
            //   ff2485f4130010       | jmp                 dword ptr [eax*4 + 0x100013f4]
            //   8b0d????????         |                     
            //   68????????           |                     
            //   51                   | push                ecx

        $sequence_3 = { 6a07 8d55e8 51 52 e8???????? 83c40c 85c0 }
            // n = 7, score = 100
            //   6a07                 | push                7
            //   8d55e8               | lea                 edx, [ebp - 0x18]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax

        $sequence_4 = { a3???????? 8b442408 48 7509 8b442404 a3???????? }
            // n = 6, score = 100
            //   a3????????           |                     
            //   8b442408             | mov                 eax, dword ptr [esp + 8]
            //   48                   | dec                 eax
            //   7509                 | jne                 0xb
            //   8b442404             | mov                 eax, dword ptr [esp + 4]
            //   a3????????           |                     

        $sequence_5 = { 40 3d00010000 7ced 6a00 8d54241c 6808010000 }
            // n = 6, score = 100
            //   40                   | inc                 eax
            //   3d00010000           | cmp                 eax, 0x100
            //   7ced                 | jl                  0xffffffef
            //   6a00                 | push                0
            //   8d54241c             | lea                 edx, [esp + 0x1c]
            //   6808010000           | push                0x108

        $sequence_6 = { 6a00 6804020000 50 56 ff15???????? 33c0 }
            // n = 6, score = 100
            //   6a00                 | push                0
            //   6804020000           | push                0x204
            //   50                   | push                eax
            //   56                   | push                esi
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax

        $sequence_7 = { 0fb601 0fb6fa 3bc7 7714 8b55fc 8a92c0cc0010 }
            // n = 6, score = 100
            //   0fb601               | movzx               eax, byte ptr [ecx]
            //   0fb6fa               | movzx               edi, dl
            //   3bc7                 | cmp                 eax, edi
            //   7714                 | ja                  0x16
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8a92c0cc0010         | mov                 dl, byte ptr [edx + 0x1000ccc0]

        $sequence_8 = { 5e 83c420 c3 53 8b1d???????? 8d4c2410 }
            // n = 6, score = 100
            //   5e                   | pop                 esi
            //   83c420               | add                 esp, 0x20
            //   c3                   | ret                 
            //   53                   | push                ebx
            //   8b1d????????         |                     
            //   8d4c2410             | lea                 ecx, [esp + 0x10]

        $sequence_9 = { 68???????? 51 8975e0 8975e8 8975dc 8975fc }
            // n = 6, score = 100
            //   68????????           |                     
            //   51                   | push                ecx
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi
            //   8975e8               | mov                 dword ptr [ebp - 0x18], esi
            //   8975dc               | mov                 dword ptr [ebp - 0x24], esi
            //   8975fc               | mov                 dword ptr [ebp - 4], esi

    condition:
        7 of them and filesize < 139264
}