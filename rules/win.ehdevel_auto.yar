rule win_ehdevel_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.ehdevel."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ehdevel"
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
        $sequence_0 = { 83c40c 8db424180c0000 e8???????? 68???????? 6a00 }
            // n = 5, score = 100
            //   83c40c               | add                 esp, 0xc
            //   8db424180c0000       | lea                 esi, [esp + 0xc18]
            //   e8????????           |                     
            //   68????????           |                     
            //   6a00                 | push                0

        $sequence_1 = { 83c404 32c0 5f 5e 8b8c24040c0000 33cc }
            // n = 6, score = 100
            //   83c404               | add                 esp, 4
            //   32c0                 | xor                 al, al
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8b8c24040c0000       | mov                 ecx, dword ptr [esp + 0xc04]
            //   33cc                 | xor                 ecx, esp

        $sequence_2 = { e8???????? 8d8db8f7ffff 51 8d9580f7ffff 52 8bde e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8d8db8f7ffff         | lea                 ecx, [ebp - 0x848]
            //   51                   | push                ecx
            //   8d9580f7ffff         | lea                 edx, [ebp - 0x880]
            //   52                   | push                edx
            //   8bde                 | mov                 ebx, esi
            //   e8????????           |                     

        $sequence_3 = { 740e 8d85f8f7ffff 50 e8???????? eb0c 8d8df8f7ffff }
            // n = 6, score = 100
            //   740e                 | je                  0x10
            //   8d85f8f7ffff         | lea                 eax, [ebp - 0x808]
            //   50                   | push                eax
            //   e8????????           |                     
            //   eb0c                 | jmp                 0xe
            //   8d8df8f7ffff         | lea                 ecx, [ebp - 0x808]

        $sequence_4 = { 33c0 8b8dc0fdffff 6bc009 0fb68408284a0210 6a08 }
            // n = 5, score = 100
            //   33c0                 | xor                 eax, eax
            //   8b8dc0fdffff         | mov                 ecx, dword ptr [ebp - 0x240]
            //   6bc009               | imul                eax, eax, 9
            //   0fb68408284a0210     | movzx               eax, byte ptr [eax + ecx + 0x10024a28]
            //   6a08                 | push                8

        $sequence_5 = { 57 ffd3 85c0 75eb ff15???????? 83f812 740d }
            // n = 7, score = 100
            //   57                   | push                edi
            //   ffd3                 | call                ebx
            //   85c0                 | test                eax, eax
            //   75eb                 | jne                 0xffffffed
            //   ff15????????         |                     
            //   83f812               | cmp                 eax, 0x12
            //   740d                 | je                  0xf

        $sequence_6 = { 8b85e8efffff 3b85e0efffff 0f85b6000000 ff15???????? 81bde8efffff00001000 0f85c4000000 47 }
            // n = 7, score = 100
            //   8b85e8efffff         | mov                 eax, dword ptr [ebp - 0x1018]
            //   3b85e0efffff         | cmp                 eax, dword ptr [ebp - 0x1020]
            //   0f85b6000000         | jne                 0xbc
            //   ff15????????         |                     
            //   81bde8efffff00001000     | cmp    dword ptr [ebp - 0x1018], 0x100000
            //   0f85c4000000         | jne                 0xca
            //   47                   | inc                 edi

        $sequence_7 = { 8b85f08bffff 8b35???????? 50 ffd6 53 ff15???????? 53 }
            // n = 7, score = 100
            //   8b85f08bffff         | mov                 eax, dword ptr [ebp - 0x7410]
            //   8b35????????         |                     
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   53                   | push                ebx

        $sequence_8 = { 68???????? e8???????? 8a442413 83c404 5f 5e 5b }
            // n = 7, score = 100
            //   68????????           |                     
            //   e8????????           |                     
            //   8a442413             | mov                 al, byte ptr [esp + 0x13]
            //   83c404               | add                 esp, 4
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_9 = { 897c2424 89442428 8944242c 89442430 ff15???????? 8b542444 }
            // n = 6, score = 100
            //   897c2424             | mov                 dword ptr [esp + 0x24], edi
            //   89442428             | mov                 dword ptr [esp + 0x28], eax
            //   8944242c             | mov                 dword ptr [esp + 0x2c], eax
            //   89442430             | mov                 dword ptr [esp + 0x30], eax
            //   ff15????????         |                     
            //   8b542444             | mov                 edx, dword ptr [esp + 0x44]

    condition:
        7 of them and filesize < 524288
}