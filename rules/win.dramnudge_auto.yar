rule win_dramnudge_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.dramnudge."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dramnudge"
        malpedia_rule_date = "20220513"
        malpedia_hash = "7f4b2229e6ae614d86d74917f6d5b41890e62a26"
        malpedia_version = "20220516"
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
        $sequence_0 = { 8945fc 8d45fc 50 e8???????? 83c408 84c0 7407 }
            // n = 7, score = 100
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   84c0                 | test                al, al
            //   7407                 | je                  9

        $sequence_1 = { 8b4308 8b50f4 42 85d2 742d 8b7308 83c6f4 }
            // n = 7, score = 100
            //   8b4308               | mov                 eax, dword ptr [ebx + 8]
            //   8b50f4               | mov                 edx, dword ptr [eax - 0xc]
            //   42                   | inc                 edx
            //   85d2                 | test                edx, edx
            //   742d                 | je                  0x2f
            //   8b7308               | mov                 esi, dword ptr [ebx + 8]
            //   83c6f4               | add                 esi, -0xc

        $sequence_2 = { 8d458c 8d8d78ffffff 50 6a00 6a00 6a00 }
            // n = 6, score = 100
            //   8d458c               | lea                 eax, [ebp - 0x74]
            //   8d8d78ffffff         | lea                 ecx, [ebp - 0x88]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_3 = { 8d4de8 8b55bc 8955f0 894db8 8b45b8 8b5008 }
            // n = 6, score = 100
            //   8d4de8               | lea                 ecx, [ebp - 0x18]
            //   8b55bc               | mov                 edx, dword ptr [ebp - 0x44]
            //   8955f0               | mov                 dword ptr [ebp - 0x10], edx
            //   894db8               | mov                 dword ptr [ebp - 0x48], ecx
            //   8b45b8               | mov                 eax, dword ptr [ebp - 0x48]
            //   8b5008               | mov                 edx, dword ptr [eax + 8]

        $sequence_4 = { 8945b4 58 8b55cc 64891500000000 5f 5e 5b }
            // n = 7, score = 100
            //   8945b4               | mov                 dword ptr [ebp - 0x4c], eax
            //   58                   | pop                 eax
            //   8b55cc               | mov                 edx, dword ptr [ebp - 0x34]
            //   64891500000000       | mov                 dword ptr fs:[0], edx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_5 = { 59 23f8 f7c701000000 0f8499000000 897330 8d8564ffffff 50 }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   23f8                 | and                 edi, eax
            //   f7c701000000         | test                edi, 1
            //   0f8499000000         | je                  0x9f
            //   897330               | mov                 dword ptr [ebx + 0x30], esi
            //   8d8564ffffff         | lea                 eax, [ebp - 0x9c]
            //   50                   | push                eax

        $sequence_6 = { 83c424 53 e8???????? 59 2b4580 03c7 898574ffffff }
            // n = 7, score = 100
            //   83c424               | add                 esp, 0x24
            //   53                   | push                ebx
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   2b4580               | sub                 eax, dword ptr [ebp - 0x80]
            //   03c7                 | add                 eax, edi
            //   898574ffffff         | mov                 dword ptr [ebp - 0x8c], eax

        $sequence_7 = { 55 8bec 8b4508 8b550c 52 83c020 50 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   52                   | push                edx
            //   83c020               | add                 eax, 0x20
            //   50                   | push                eax

        $sequence_8 = { 85c0 7421 53 e8???????? 59 50 53 }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   7421                 | je                  0x23
            //   53                   | push                ebx
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   50                   | push                eax
            //   53                   | push                ebx

        $sequence_9 = { 894204 b8???????? ff45f8 33d2 8b4d08 8901 }
            // n = 6, score = 100
            //   894204               | mov                 dword ptr [edx + 4], eax
            //   b8????????           |                     
            //   ff45f8               | inc                 dword ptr [ebp - 8]
            //   33d2                 | xor                 edx, edx
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8901                 | mov                 dword ptr [ecx], eax

    condition:
        7 of them and filesize < 1294336
}