rule win_rcs_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.rcs."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rcs"
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
        $sequence_0 = { 89442452 89442456 8944245a 8944245e 89442462 89442466 8944246a }
            // n = 7, score = 200
            //   89442452             | mov                 dword ptr [esp + 0x52], eax
            //   89442456             | mov                 dword ptr [esp + 0x56], eax
            //   8944245a             | mov                 dword ptr [esp + 0x5a], eax
            //   8944245e             | mov                 dword ptr [esp + 0x5e], eax
            //   89442462             | mov                 dword ptr [esp + 0x62], eax
            //   89442466             | mov                 dword ptr [esp + 0x66], eax
            //   8944246a             | mov                 dword ptr [esp + 0x6a], eax

        $sequence_1 = { 85ff 0f84d4000000 57 e8???????? }
            // n = 4, score = 200
            //   85ff                 | test                edi, edi
            //   0f84d4000000         | je                  0xda
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_2 = { ff15???????? 85c0 740d ff15???????? 33c0 }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   740d                 | je                  0xf
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax

        $sequence_3 = { e8???????? 83c430 6aff 68???????? }
            // n = 4, score = 200
            //   e8????????           |                     
            //   83c430               | add                 esp, 0x30
            //   6aff                 | push                -1
            //   68????????           |                     

        $sequence_4 = { 40 68???????? 50 e8???????? 83c40c eb0d }
            // n = 6, score = 200
            //   40                   | inc                 eax
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   eb0d                 | jmp                 0xf

        $sequence_5 = { 6a00 6880000000 6a01 6a00 6a05 }
            // n = 5, score = 200
            //   6a00                 | push                0
            //   6880000000           | push                0x80
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   6a05                 | push                5

        $sequence_6 = { ff15???????? 5f 5e 5d 5b 33c0 }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx
            //   33c0                 | xor                 eax, eax

        $sequence_7 = { 66898552f4fbff 0fb78552f4fbff 50 ff96b4000000 8b7dec 8b16 }
            // n = 6, score = 100
            //   66898552f4fbff       | mov                 word ptr [ebp - 0x40bae], ax
            //   0fb78552f4fbff       | movzx               eax, word ptr [ebp - 0x40bae]
            //   50                   | push                eax
            //   ff96b4000000         | call                dword ptr [esi + 0xb4]
            //   8b7dec               | mov                 edi, dword ptr [ebp - 0x14]
            //   8b16                 | mov                 edx, dword ptr [esi]

        $sequence_8 = { 8b7d08 8b37 81c6d2000000 56 ff5708 8945f8 8b7d08 }
            // n = 7, score = 100
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8b37                 | mov                 esi, dword ptr [edi]
            //   81c6d2000000         | add                 esi, 0xd2
            //   56                   | push                esi
            //   ff5708               | call                dword ptr [edi + 8]
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]

        $sequence_9 = { 83c410 8d8594f8fbff 50 ff968c000000 }
            // n = 4, score = 100
            //   83c410               | add                 esp, 0x10
            //   8d8594f8fbff         | lea                 eax, dword ptr [ebp - 0x4076c]
            //   50                   | push                eax
            //   ff968c000000         | call                dword ptr [esi + 0x8c]

        $sequence_10 = { 8b5d0c 8a1c3b 881c3e 8b7dfc 8b7508 }
            // n = 5, score = 100
            //   8b5d0c               | mov                 ebx, dword ptr [ebp + 0xc]
            //   8a1c3b               | mov                 bl, byte ptr [ebx + edi]
            //   881c3e               | mov                 byte ptr [esi + edi], bl
            //   8b7dfc               | mov                 edi, dword ptr [ebp - 4]
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]

        $sequence_11 = { 50 6a20 6a01 6a64 6a6e ff5660 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   6a20                 | push                0x20
            //   6a01                 | push                1
            //   6a64                 | push                0x64
            //   6a6e                 | push                0x6e
            //   ff5660               | call                dword ptr [esi + 0x60]

        $sequence_12 = { ff5704 894774 8b7d08 8b37 81c65a020000 }
            // n = 5, score = 100
            //   ff5704               | call                dword ptr [edi + 4]
            //   894774               | mov                 dword ptr [edi + 0x74], eax
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8b37                 | mov                 esi, dword ptr [edi]
            //   81c65a020000         | add                 esi, 0x25a

        $sequence_13 = { 81733c53a10fca 0b29 5f deb3fab652b4 }
            // n = 4, score = 100
            //   81733c53a10fca       | xor                 dword ptr [ebx + 0x3c], 0xca0fa153
            //   0b29                 | or                  ebp, dword ptr [ecx]
            //   5f                   | pop                 edi
            //   deb3fab652b4         | fidiv               word ptr [ebx - 0x4bad4906]

        $sequence_14 = { 83ec50 8b44245c 53 8b5c2458 55 }
            // n = 5, score = 100
            //   83ec50               | sub                 esp, 0x50
            //   8b44245c             | mov                 eax, dword ptr [esp + 0x5c]
            //   53                   | push                ebx
            //   8b5c2458             | mov                 ebx, dword ptr [esp + 0x58]
            //   55                   | push                ebp

        $sequence_15 = { 09c0 740c c785a0f9fbff00e0ffff eb0a c785a0f9fbff80faffff }
            // n = 5, score = 100
            //   09c0                 | or                  eax, eax
            //   740c                 | je                  0xe
            //   c785a0f9fbff00e0ffff     | mov    dword ptr [ebp - 0x40660], 0xffffe000
            //   eb0a                 | jmp                 0xc
            //   c785a0f9fbff80faffff     | mov    dword ptr [ebp - 0x40660], 0xfffffa80

        $sequence_16 = { 8345ec04 817dec00010000 72b0 817dec00010000 0f84b8000000 8b86dc000000 833800 }
            // n = 7, score = 100
            //   8345ec04             | add                 dword ptr [ebp - 0x14], 4
            //   817dec00010000       | cmp                 dword ptr [ebp - 0x14], 0x100
            //   72b0                 | jb                  0xffffffb2
            //   817dec00010000       | cmp                 dword ptr [ebp - 0x14], 0x100
            //   0f84b8000000         | je                  0xbe
            //   8b86dc000000         | mov                 eax, dword ptr [esi + 0xdc]
            //   833800               | cmp                 dword ptr [eax], 0

    condition:
        7 of them and filesize < 11501568
}