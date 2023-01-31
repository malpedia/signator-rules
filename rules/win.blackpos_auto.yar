rule win_blackpos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.blackpos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackpos"
        malpedia_rule_date = "20230124"
        malpedia_hash = "2ee0eebba83dce3d019a90519f2f972c0fcf9686"
        malpedia_version = "20230125"
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
        $sequence_0 = { 56 e8???????? 83c40c 85c0 745f 57 68???????? }
            // n = 7, score = 100
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   745f                 | je                  0x61
            //   57                   | push                edi
            //   68????????           |                     

        $sequence_1 = { 83c40c 85c0 740f 8b8df8fbffff 89481c }
            // n = 5, score = 100
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   740f                 | je                  0x11
            //   8b8df8fbffff         | mov                 ecx, dword ptr [ebp - 0x408]
            //   89481c               | mov                 dword ptr [eax + 0x1c], ecx

        $sequence_2 = { c1f805 8d148560c45800 8b0a 83e61f c1e606 03ce }
            // n = 6, score = 100
            //   c1f805               | sar                 eax, 5
            //   8d148560c45800       | lea                 edx, [eax*4 + 0x58c460]
            //   8b0a                 | mov                 ecx, dword ptr [edx]
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   03ce                 | add                 ecx, esi

        $sequence_3 = { 6a02 6a10 68ff010f00 68???????? ff35???????? 57 ff15???????? }
            // n = 7, score = 100
            //   6a02                 | push                2
            //   6a10                 | push                0x10
            //   68ff010f00           | push                0xf01ff
            //   68????????           |                     
            //   ff35????????         |                     
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_4 = { 50 e8???????? 59 eb52 }
            // n = 4, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   eb52                 | jmp                 0x54

        $sequence_5 = { 50 8d85b8f4ffff 50 53 6800000008 6a01 53 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d85b8f4ffff         | lea                 eax, [ebp - 0xb48]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   6800000008           | push                0x8000000
            //   6a01                 | push                1
            //   53                   | push                ebx

        $sequence_6 = { 66890c45a4c25800 40 ebe8 33c0 8945e4 }
            // n = 5, score = 100
            //   66890c45a4c25800     | mov                 word ptr [eax*2 + 0x58c2a4], cx
            //   40                   | inc                 eax
            //   ebe8                 | jmp                 0xffffffea
            //   33c0                 | xor                 eax, eax
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax

        $sequence_7 = { 85c0 0f8413010000 c785f8f7ffffb8e04100 33ff ffb5f8f7ffff }
            // n = 5, score = 100
            //   85c0                 | test                eax, eax
            //   0f8413010000         | je                  0x119
            //   c785f8f7ffffb8e04100     | mov    dword ptr [ebp - 0x808], 0x41e0b8
            //   33ff                 | xor                 edi, edi
            //   ffb5f8f7ffff         | push                dword ptr [ebp - 0x808]

        $sequence_8 = { 894dec eb07 c745ec2a040000 8945f0 8b4514 8945f4 8b4518 }
            // n = 7, score = 100
            //   894dec               | mov                 dword ptr [ebp - 0x14], ecx
            //   eb07                 | jmp                 9
            //   c745ec2a040000       | mov                 dword ptr [ebp - 0x14], 0x42a
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b4518               | mov                 eax, dword ptr [ebp + 0x18]

        $sequence_9 = { ffd6 85c0 7517 e8???????? eb10 8d45c4 50 }
            // n = 7, score = 100
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   7517                 | jne                 0x19
            //   e8????????           |                     
            //   eb10                 | jmp                 0x12
            //   8d45c4               | lea                 eax, [ebp - 0x3c]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 3293184
}