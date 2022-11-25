rule win_penco_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.penco."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.penco"
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
        $sequence_0 = { 8914b1 8b3481 03f6 03f6 39041e 7532 5f }
            // n = 7, score = 100
            //   8914b1               | mov                 dword ptr [ecx + esi*4], edx
            //   8b3481               | mov                 esi, dword ptr [ecx + eax*4]
            //   03f6                 | add                 esi, esi
            //   03f6                 | add                 esi, esi
            //   39041e               | cmp                 dword ptr [esi + ebx], eax
            //   7532                 | jne                 0x34
            //   5f                   | pop                 edi

        $sequence_1 = { 8b8d4cfeffff 51 8b55e4 52 ff15???????? eb7c 68???????? }
            // n = 7, score = 100
            //   8b8d4cfeffff         | mov                 ecx, dword ptr [ebp - 0x1b4]
            //   51                   | push                ecx
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   eb7c                 | jmp                 0x7e
            //   68????????           |                     

        $sequence_2 = { 3bf3 7e30 8d4500 50 ff15???????? }
            // n = 5, score = 100
            //   3bf3                 | cmp                 esi, ebx
            //   7e30                 | jle                 0x32
            //   8d4500               | lea                 eax, [ebp]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_3 = { 889da0010000 68feff0000 53 8d85a1010000 50 e8???????? }
            // n = 6, score = 100
            //   889da0010000         | mov                 byte ptr [ebp + 0x1a0], bl
            //   68feff0000           | push                0xfffe
            //   53                   | push                ebx
            //   8d85a1010000         | lea                 eax, [ebp + 0x1a1]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_4 = { 03dd 53 e8???????? 83c40c e9???????? 57 ff15???????? }
            // n = 7, score = 100
            //   03dd                 | add                 ebx, ebp
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   e9????????           |                     
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_5 = { 8b0d???????? 898d34f5ffff 8b15???????? 899538f5ffff a0???????? 88853cf5ffff 8b4d0c }
            // n = 7, score = 100
            //   8b0d????????         |                     
            //   898d34f5ffff         | mov                 dword ptr [ebp - 0xacc], ecx
            //   8b15????????         |                     
            //   899538f5ffff         | mov                 dword ptr [ebp - 0xac8], edx
            //   a0????????           |                     
            //   88853cf5ffff         | mov                 byte ptr [ebp - 0xac4], al
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]

        $sequence_6 = { 51 8d542424 52 8d44241c 50 6aff 8d4c2420 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   8d542424             | lea                 edx, [esp + 0x24]
            //   52                   | push                edx
            //   8d44241c             | lea                 eax, [esp + 0x1c]
            //   50                   | push                eax
            //   6aff                 | push                -1
            //   8d4c2420             | lea                 ecx, [esp + 0x20]

        $sequence_7 = { 57 50 8d45f0 64a300000000 8b858c000000 8945e4 8bb594000000 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   50                   | push                eax
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8b858c000000         | mov                 eax, dword ptr [ebp + 0x8c]
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8bb594000000         | mov                 esi, dword ptr [ebp + 0x94]

        $sequence_8 = { 8955fc 50 e8???????? 6c 69737470726f63 005889 }
            // n = 6, score = 100
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   50                   | push                eax
            //   e8????????           |                     
            //   6c                   | insb                byte ptr es:[edi], dx
            //   69737470726f63       | imul                esi, dword ptr [ebx + 0x74], 0x636f7270
            //   005889               | add                 byte ptr [eax - 0x77], bl

        $sequence_9 = { 8b349528ec3400 8b542414 894c241c 8b4c2410 c1e910 0fb6f9 3334bd28e83400 }
            // n = 7, score = 100
            //   8b349528ec3400       | mov                 esi, dword ptr [edx*4 + 0x34ec28]
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   894c241c             | mov                 dword ptr [esp + 0x1c], ecx
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   c1e910               | shr                 ecx, 0x10
            //   0fb6f9               | movzx               edi, cl
            //   3334bd28e83400       | xor                 esi, dword ptr [edi*4 + 0x34e828]

    condition:
        7 of them and filesize < 319488
}