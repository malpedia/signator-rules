rule win_atmii_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.atmii."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.atmii"
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
        $sequence_0 = { 5d c3 33c0 8945dd 8945e1 8945e5 }
            // n = 6, score = 100
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   33c0                 | xor                 eax, eax
            //   8945dd               | mov                 dword ptr [ebp - 0x23], eax
            //   8945e1               | mov                 dword ptr [ebp - 0x1f], eax
            //   8945e5               | mov                 dword ptr [ebp - 0x1b], eax

        $sequence_1 = { 68???????? 52 ffd7 8d85dcfbffff 50 e8???????? 83c414 }
            // n = 7, score = 100
            //   68????????           |                     
            //   52                   | push                edx
            //   ffd7                 | call                edi
            //   8d85dcfbffff         | lea                 eax, dword ptr [ebp - 0x424]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14

        $sequence_2 = { 7524 8b45fc 83c00d 50 8b4dfc }
            // n = 5, score = 100
            //   7524                 | jne                 0x26
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   83c00d               | add                 eax, 0xd
            //   50                   | push                eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_3 = { ff15???????? 8b3d???????? 85c0 8b45f4 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   8b3d????????         |                     
            //   85c0                 | test                eax, eax
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_4 = { 8a4dff 03d6 eb3a 83481840 }
            // n = 4, score = 100
            //   8a4dff               | mov                 cl, byte ptr [ebp - 1]
            //   03d6                 | add                 edx, esi
            //   eb3a                 | jmp                 0x3c
            //   83481840             | or                  dword ptr [eax + 0x18], 0x40

        $sequence_5 = { ffd7 6800020000 8d8d28fbffff 51 6a00 ff15???????? 50 }
            // n = 7, score = 100
            //   ffd7                 | call                edi
            //   6800020000           | push                0x200
            //   8d8d28fbffff         | lea                 ecx, dword ptr [ebp - 0x4d8]
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   50                   | push                eax

        $sequence_6 = { 6a05 8d45ec 50 51 }
            // n = 4, score = 100
            //   6a05                 | push                5
            //   8d45ec               | lea                 eax, dword ptr [ebp - 0x14]
            //   50                   | push                eax
            //   51                   | push                ecx

        $sequence_7 = { 742d 68???????? 68c3000000 8d85f8fcffff 68???????? 50 }
            // n = 6, score = 100
            //   742d                 | je                  0x2f
            //   68????????           |                     
            //   68c3000000           | push                0xc3
            //   8d85f8fcffff         | lea                 eax, dword ptr [ebp - 0x308]
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_8 = { 57 68???????? 68c7000000 8d85fcfbffff 68???????? }
            // n = 5, score = 100
            //   57                   | push                edi
            //   68????????           |                     
            //   68c7000000           | push                0xc7
            //   8d85fcfbffff         | lea                 eax, dword ptr [ebp - 0x404]
            //   68????????           |                     

        $sequence_9 = { 6a00 68???????? 68???????? ffd6 8b35???????? 8d95fcfeffff 52 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   68????????           |                     
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   8b35????????         |                     
            //   8d95fcfeffff         | lea                 edx, dword ptr [ebp - 0x104]
            //   52                   | push                edx

        $sequence_10 = { 8b5608 8b3d???????? 83c414 68???????? 52 68???????? }
            // n = 6, score = 100
            //   8b5608               | mov                 edx, dword ptr [esi + 8]
            //   8b3d????????         |                     
            //   83c414               | add                 esp, 0x14
            //   68????????           |                     
            //   52                   | push                edx
            //   68????????           |                     

        $sequence_11 = { 51 ff15???????? 50 8b5508 52 8b45fc 50 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   50                   | push                eax
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   52                   | push                edx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax

        $sequence_12 = { 8d8dd4fdffff 6a00 51 e8???????? 83c420 8d95d0fdffff }
            // n = 6, score = 100
            //   8d8dd4fdffff         | lea                 ecx, dword ptr [ebp - 0x22c]
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c420               | add                 esp, 0x20
            //   8d95d0fdffff         | lea                 edx, dword ptr [ebp - 0x230]

        $sequence_13 = { 68???????? 85f6 0f84c8000000 6879020000 8d8500feffff }
            // n = 5, score = 100
            //   68????????           |                     
            //   85f6                 | test                esi, esi
            //   0f84c8000000         | je                  0xce
            //   6879020000           | push                0x279
            //   8d8500feffff         | lea                 eax, dword ptr [ebp - 0x200]

        $sequence_14 = { 687e020000 8d8d00feffff 68???????? 51 ff15???????? 83c410 }
            // n = 6, score = 100
            //   687e020000           | push                0x27e
            //   8d8d00feffff         | lea                 ecx, dword ptr [ebp - 0x200]
            //   68????????           |                     
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   83c410               | add                 esp, 0x10

        $sequence_15 = { 6a00 51 56 ffd7 56 }
            // n = 5, score = 100
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   56                   | push                esi
            //   ffd7                 | call                edi
            //   56                   | push                esi

    condition:
        7 of them and filesize < 49152
}