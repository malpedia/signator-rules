rule win_darkloader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.darkloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkloader"
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
        $sequence_0 = { 0fb73470 8b442428 ff701c 55 }
            // n = 4, score = 100
            //   0fb73470             | movzx               esi, word ptr [eax + esi*2]
            //   8b442428             | mov                 eax, dword ptr [esp + 0x28]
            //   ff701c               | push                dword ptr [eax + 0x1c]
            //   55                   | push                ebp

        $sequence_1 = { ff15???????? 8bc8 83c40c 85c9 742c 57 8b7c2414 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8bc8                 | mov                 ecx, eax
            //   83c40c               | add                 esp, 0xc
            //   85c9                 | test                ecx, ecx
            //   742c                 | je                  0x2e
            //   57                   | push                edi
            //   8b7c2414             | mov                 edi, dword ptr [esp + 0x14]

        $sequence_2 = { 7415 32c0 89442414 84c0 740b 80f90d }
            // n = 6, score = 100
            //   7415                 | je                  0x17
            //   32c0                 | xor                 al, al
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   84c0                 | test                al, al
            //   740b                 | je                  0xd
            //   80f90d               | cmp                 cl, 0xd

        $sequence_3 = { 41 880416 42 3b5510 7cf4 5e 5d }
            // n = 7, score = 100
            //   41                   | inc                 ecx
            //   880416               | mov                 byte ptr [esi + edx], al
            //   42                   | inc                 edx
            //   3b5510               | cmp                 edx, dword ptr [ebp + 0x10]
            //   7cf4                 | jl                  0xfffffff6
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp

        $sequence_4 = { 03c3 8a08 3a0f 751a 84c9 7412 }
            // n = 6, score = 100
            //   03c3                 | add                 eax, ebx
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   3a0f                 | cmp                 cl, byte ptr [edi]
            //   751a                 | jne                 0x1c
            //   84c9                 | test                cl, cl
            //   7412                 | je                  0x14

        $sequence_5 = { 743b 3c3a 7437 3c3f 7433 3c3d 742f }
            // n = 7, score = 100
            //   743b                 | je                  0x3d
            //   3c3a                 | cmp                 al, 0x3a
            //   7437                 | je                  0x39
            //   3c3f                 | cmp                 al, 0x3f
            //   7433                 | je                  0x35
            //   3c3d                 | cmp                 al, 0x3d
            //   742f                 | je                  0x31

        $sequence_6 = { 56 6a04 68???????? ffd3 }
            // n = 4, score = 100
            //   56                   | push                esi
            //   6a04                 | push                4
            //   68????????           |                     
            //   ffd3                 | call                ebx

        $sequence_7 = { 668996ae010000 8b400c 6a10 51 ff36 8b00 }
            // n = 6, score = 100
            //   668996ae010000       | mov                 word ptr [esi + 0x1ae], dx
            //   8b400c               | mov                 eax, dword ptr [eax + 0xc]
            //   6a10                 | push                0x10
            //   51                   | push                ecx
            //   ff36                 | push                dword ptr [esi]
            //   8b00                 | mov                 eax, dword ptr [eax]

        $sequence_8 = { 84c0 75f9 2bce 3bd1 72e3 8b35???????? 6a3a }
            // n = 7, score = 100
            //   84c0                 | test                al, al
            //   75f9                 | jne                 0xfffffffb
            //   2bce                 | sub                 ecx, esi
            //   3bd1                 | cmp                 edx, ecx
            //   72e3                 | jb                  0xffffffe5
            //   8b35????????         |                     
            //   6a3a                 | push                0x3a

        $sequence_9 = { 896c241c c644241b01 ffd6 2bc5 2bc7 8be8 }
            // n = 6, score = 100
            //   896c241c             | mov                 dword ptr [esp + 0x1c], ebp
            //   c644241b01           | mov                 byte ptr [esp + 0x1b], 1
            //   ffd6                 | call                esi
            //   2bc5                 | sub                 eax, ebp
            //   2bc7                 | sub                 eax, edi
            //   8be8                 | mov                 ebp, eax

    condition:
        7 of them and filesize < 124928
}