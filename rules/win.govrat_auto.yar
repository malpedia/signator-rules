rule win_govrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.govrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.govrat"
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
        $sequence_0 = { 890c96 898c8600100000 ff4710 8b4708 ff07 4b }
            // n = 6, score = 200
            //   890c96               | mov                 dword ptr [esi + edx*4], ecx
            //   898c8600100000       | mov                 dword ptr [esi + eax*4 + 0x1000], ecx
            //   ff4710               | inc                 dword ptr [edi + 0x10]
            //   8b4708               | mov                 eax, dword ptr [edi + 8]
            //   ff07                 | inc                 dword ptr [edi]
            //   4b                   | dec                 ebx

        $sequence_1 = { 8b08 50 ff510c ff751c ff7510 ff750c e8???????? }
            // n = 7, score = 200
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   50                   | push                eax
            //   ff510c               | call                dword ptr [ecx + 0xc]
            //   ff751c               | push                dword ptr [ebp + 0x1c]
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   e8????????           |                     

        $sequence_2 = { 75f7 5f 5e 5b c9 c20800 837c240401 }
            // n = 7, score = 200
            //   75f7                 | jne                 0xfffffff9
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   c20800               | ret                 8
            //   837c240401           | cmp                 dword ptr [esp + 4], 1

        $sequence_3 = { 0f8410010000 81f9777f4530 0f8404010000 81f99f761f60 eb2a 81f9d41650b0 0f84f0000000 }
            // n = 7, score = 200
            //   0f8410010000         | je                  0x116
            //   81f9777f4530         | cmp                 ecx, 0x30457f77
            //   0f8404010000         | je                  0x10a
            //   81f99f761f60         | cmp                 ecx, 0x601f769f
            //   eb2a                 | jmp                 0x2c
            //   81f9d41650b0         | cmp                 ecx, 0xb05016d4
            //   0f84f0000000         | je                  0xf6

        $sequence_4 = { 51 83a64c19030000 53 57 33c0 8dbe3c190300 ab }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   83a64c19030000       | and                 dword ptr [esi + 0x3194c], 0
            //   53                   | push                ebx
            //   57                   | push                edi
            //   33c0                 | xor                 eax, eax
            //   8dbe3c190300         | lea                 edi, [esi + 0x3193c]
            //   ab                   | stosd               dword ptr es:[edi], eax

        $sequence_5 = { 83ec38 53 8b5d08 56 57 6a0c 59 }
            // n = 7, score = 200
            //   83ec38               | sub                 esp, 0x38
            //   53                   | push                ebx
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   56                   | push                esi
            //   57                   | push                edi
            //   6a0c                 | push                0xc
            //   59                   | pop                 ecx

        $sequence_6 = { 3bc1 75f7 eb44 8b1e 8bf8 8d77fc }
            // n = 6, score = 200
            //   3bc1                 | cmp                 eax, ecx
            //   75f7                 | jne                 0xfffffff9
            //   eb44                 | jmp                 0x46
            //   8b1e                 | mov                 ebx, dword ptr [esi]
            //   8bf8                 | mov                 edi, eax
            //   8d77fc               | lea                 esi, [edi - 4]

        $sequence_7 = { 72f2 8b4508 ff8638190300 8918 8bc7 5f 5b }
            // n = 7, score = 200
            //   72f2                 | jb                  0xfffffff4
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   ff8638190300         | inc                 dword ptr [esi + 0x31938]
            //   8918                 | mov                 dword ptr [eax], ebx
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx

        $sequence_8 = { 7512 ff75e8 8b35???????? ffd6 ff75e4 ffd6 ebbd }
            // n = 7, score = 200
            //   7512                 | jne                 0x14
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   8b35????????         |                     
            //   ffd6                 | call                esi
            //   ff75e4               | push                dword ptr [ebp - 0x1c]
            //   ffd6                 | call                esi
            //   ebbd                 | jmp                 0xffffffbf

        $sequence_9 = { eb1e ff750c 8d45f0 50 57 ff7508 53 }
            // n = 7, score = 200
            //   eb1e                 | jmp                 0x20
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax
            //   57                   | push                edi
            //   ff7508               | push                dword ptr [ebp + 8]
            //   53                   | push                ebx

    condition:
        7 of them and filesize < 761856
}