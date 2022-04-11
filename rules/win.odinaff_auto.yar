rule win_odinaff_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.odinaff."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.odinaff"
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
        $sequence_0 = { 56 6804010000 8bf8 ff15???????? 57 6a00 }
            // n = 6, score = 200
            //   56                   | push                esi
            //   6804010000           | push                0x104
            //   8bf8                 | mov                 edi, eax
            //   ff15????????         |                     
            //   57                   | push                edi
            //   6a00                 | push                0

        $sequence_1 = { 83ec08 56 57 8b3d???????? 680000a000 6a08 }
            // n = 6, score = 200
            //   83ec08               | sub                 esp, 8
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b3d????????         |                     
            //   680000a000           | push                0xa00000
            //   6a08                 | push                8

        $sequence_2 = { 83c404 56 6a00 ffd7 8b35???????? 50 ffd6 }
            // n = 7, score = 200
            //   83c404               | add                 esp, 4
            //   56                   | push                esi
            //   6a00                 | push                0
            //   ffd7                 | call                edi
            //   8b35????????         |                     
            //   50                   | push                eax
            //   ffd6                 | call                esi

        $sequence_3 = { eb23 6800100000 6a08 ffd7 }
            // n = 4, score = 200
            //   eb23                 | jmp                 0x25
            //   6800100000           | push                0x1000
            //   6a08                 | push                8
            //   ffd7                 | call                edi

        $sequence_4 = { 8b45f4 8b4dfc 50 6a00 6a00 }
            // n = 5, score = 200
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_5 = { 8bf0 68???????? 56 ff15???????? 8b1d???????? 83c40c }
            // n = 6, score = 200
            //   8bf0                 | mov                 esi, eax
            //   68????????           |                     
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8b1d????????         |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_6 = { 8945fc 8d4598 50 bf00006884 c745ec80430000 e8???????? 8b4df4 }
            // n = 7, score = 200
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8d4598               | lea                 eax, dword ptr [ebp - 0x68]
            //   50                   | push                eax
            //   bf00006884           | mov                 edi, 0x84680000
            //   c745ec80430000       | mov                 dword ptr [ebp - 0x14], 0x4380
            //   e8????????           |                     
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_7 = { 89848d00fcffff 41 81f900010000 72d7 83c8ff 33c9 }
            // n = 6, score = 200
            //   89848d00fcffff       | mov                 dword ptr [ebp + ecx*4 - 0x400], eax
            //   41                   | inc                 ecx
            //   81f900010000         | cmp                 ecx, 0x100
            //   72d7                 | jb                  0xffffffd9
            //   83c8ff               | or                  eax, 0xffffffff
            //   33c9                 | xor                 ecx, ecx

        $sequence_8 = { 52 ff15???????? 85c0 7505 bf0030e884 6a00 6a00 }
            // n = 7, score = 200
            //   52                   | push                edx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7
            //   bf0030e884           | mov                 edi, 0x84e83000
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_9 = { ffd7 50 ff15???????? 8b4d0c 6a00 6880000000 6a02 }
            // n = 7, score = 200
            //   ffd7                 | call                edi
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   6a00                 | push                0
            //   6880000000           | push                0x80
            //   6a02                 | push                2

    condition:
        7 of them and filesize < 73728
}