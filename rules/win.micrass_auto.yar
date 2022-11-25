rule win_micrass_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.micrass."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.micrass"
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
        $sequence_0 = { 57 ff750c ff750c ffb5a83fffff 6aff 68???????? 56 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ffb5a83fffff         | push                dword ptr [ebp - 0xc058]
            //   6aff                 | push                -1
            //   68????????           |                     
            //   56                   | push                esi

        $sequence_1 = { 2b8504faffff 8b8d04faffff 898dfcf9ffff 8985f8f9ffff }
            // n = 4, score = 100
            //   2b8504faffff         | sub                 eax, dword ptr [ebp - 0x5fc]
            //   8b8d04faffff         | mov                 ecx, dword ptr [ebp - 0x5fc]
            //   898dfcf9ffff         | mov                 dword ptr [ebp - 0x604], ecx
            //   8985f8f9ffff         | mov                 dword ptr [ebp - 0x608], eax

        $sequence_2 = { c7855cfffffff4f4f4f4 c78560fffffff4f4f4f4 c78564fffffff4f4f4f4 c78568fffffff4f4f4f4 c7856cffffffa39d9abc }
            // n = 5, score = 100
            //   c7855cfffffff4f4f4f4     | mov    dword ptr [ebp - 0xa4], 0xf4f4f4f4
            //   c78560fffffff4f4f4f4     | mov    dword ptr [ebp - 0xa0], 0xf4f4f4f4
            //   c78564fffffff4f4f4f4     | mov    dword ptr [ebp - 0x9c], 0xf4f4f4f4
            //   c78568fffffff4f4f4f4     | mov    dword ptr [ebp - 0x98], 0xf4f4f4f4
            //   c7856cffffffa39d9abc     | mov    dword ptr [ebp - 0x94], 0xbc9a9da3

        $sequence_3 = { 33ff 8985a83fffff 89bdb03fffff 89bdbc3fffff bb18600000 57 }
            // n = 6, score = 100
            //   33ff                 | xor                 edi, edi
            //   8985a83fffff         | mov                 dword ptr [ebp - 0xc058], eax
            //   89bdb03fffff         | mov                 dword ptr [ebp - 0xc050], edi
            //   89bdbc3fffff         | mov                 dword ptr [ebp - 0xc044], edi
            //   bb18600000           | mov                 ebx, 0x6018
            //   57                   | push                edi

        $sequence_4 = { 8d853cffffff 50 57 ffd6 a3???????? 391d???????? }
            // n = 6, score = 100
            //   8d853cffffff         | lea                 eax, [ebp - 0xc4]
            //   50                   | push                eax
            //   57                   | push                edi
            //   ffd6                 | call                esi
            //   a3????????           |                     
            //   391d????????         |                     

        $sequence_5 = { 8d85acfeffff 50 57 ffd6 a3???????? 391d???????? }
            // n = 6, score = 100
            //   8d85acfeffff         | lea                 eax, [ebp - 0x154]
            //   50                   | push                eax
            //   57                   | push                edi
            //   ffd6                 | call                esi
            //   a3????????           |                     
            //   391d????????         |                     

        $sequence_6 = { 3b4d0c 72f3 5d c3 }
            // n = 4, score = 100
            //   3b4d0c               | cmp                 ecx, dword ptr [ebp + 0xc]
            //   72f3                 | jb                  0xfffffff5
            //   5d                   | pop                 ebp
            //   c3                   | ret                 

        $sequence_7 = { 50 68???????? 56 ff15???????? 85c0 741b }
            // n = 6, score = 100
            //   50                   | push                eax
            //   68????????           |                     
            //   56                   | push                esi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   741b                 | je                  0x1d

        $sequence_8 = { e8???????? 59 837e4400 57 bf???????? }
            // n = 5, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   837e4400             | cmp                 dword ptr [esi + 0x44], 0
            //   57                   | push                edi
            //   bf????????           |                     

        $sequence_9 = { 8bc6 c1f805 8b0485a0dd4000 83e61f c1e606 8d443004 8020fd }
            // n = 7, score = 100
            //   8bc6                 | mov                 eax, esi
            //   c1f805               | sar                 eax, 5
            //   8b0485a0dd4000       | mov                 eax, dword ptr [eax*4 + 0x40dda0]
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   8d443004             | lea                 eax, [eax + esi + 4]
            //   8020fd               | and                 byte ptr [eax], 0xfd

    condition:
        7 of them and filesize < 163840
}