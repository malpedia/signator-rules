rule win_rektloader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.rektloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rektloader"
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
        $sequence_0 = { 8b45b8 e9???????? 8d4d80 e8???????? 8b45d8 50 8d4d80 }
            // n = 7, score = 100
            //   8b45b8               | mov                 eax, dword ptr [ebp - 0x48]
            //   e9????????           |                     
            //   8d4d80               | lea                 ecx, dword ptr [ebp - 0x80]
            //   e8????????           |                     
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]
            //   50                   | push                eax
            //   8d4d80               | lea                 ecx, dword ptr [ebp - 0x80]

        $sequence_1 = { 7501 cc 85ff 7528 e8???????? 56 6a41 }
            // n = 7, score = 100
            //   7501                 | jne                 3
            //   cc                   | int3                
            //   85ff                 | test                edi, edi
            //   7528                 | jne                 0x2a
            //   e8????????           |                     
            //   56                   | push                esi
            //   6a41                 | push                0x41

        $sequence_2 = { 7402 eb48 68???????? 68???????? 6a00 68d9050000 68???????? }
            // n = 7, score = 100
            //   7402                 | je                  4
            //   eb48                 | jmp                 0x4a
            //   68????????           |                     
            //   68????????           |                     
            //   6a00                 | push                0
            //   68d9050000           | push                0x5d9
            //   68????????           |                     

        $sequence_3 = { 898178995600 68???????? 8b55fc 52 ff15???????? 3305???????? b904000000 }
            // n = 7, score = 100
            //   898178995600         | mov                 dword ptr [ecx + 0x569978], eax
            //   68????????           |                     
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   3305????????         |                     
            //   b904000000           | mov                 ecx, 4

        $sequence_4 = { 8d8d74fdffff e8???????? c645fc00 8d8d98fdffff e8???????? c78518faffff00000000 c745fcffffffff }
            // n = 7, score = 100
            //   8d8d74fdffff         | lea                 ecx, dword ptr [ebp - 0x28c]
            //   e8????????           |                     
            //   c645fc00             | mov                 byte ptr [ebp - 4], 0
            //   8d8d98fdffff         | lea                 ecx, dword ptr [ebp - 0x268]
            //   e8????????           |                     
            //   c78518faffff00000000     | mov    dword ptr [ebp - 0x5e8], 0
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff

        $sequence_5 = { 7702 eb48 68???????? 68???????? 6a00 68840c0000 68???????? }
            // n = 7, score = 100
            //   7702                 | ja                  4
            //   eb48                 | jmp                 0x4a
            //   68????????           |                     
            //   68????????           |                     
            //   6a00                 | push                0
            //   68840c0000           | push                0xc84
            //   68????????           |                     

        $sequence_6 = { 3b4524 750b 8b8d68ffffff 894d88 eb06 8b55a0 895588 }
            // n = 7, score = 100
            //   3b4524               | cmp                 eax, dword ptr [ebp + 0x24]
            //   750b                 | jne                 0xd
            //   8b8d68ffffff         | mov                 ecx, dword ptr [ebp - 0x98]
            //   894d88               | mov                 dword ptr [ebp - 0x78], ecx
            //   eb06                 | jmp                 8
            //   8b55a0               | mov                 edx, dword ptr [ebp - 0x60]
            //   895588               | mov                 dword ptr [ebp - 0x78], edx

        $sequence_7 = { 8d8d74fdffff e8???????? 898514faffff c645fc02 b802000000 6bc800 }
            // n = 6, score = 100
            //   8d8d74fdffff         | lea                 ecx, dword ptr [ebp - 0x28c]
            //   e8????????           |                     
            //   898514faffff         | mov                 dword ptr [ebp - 0x5ec], eax
            //   c645fc02             | mov                 byte ptr [ebp - 4], 2
            //   b802000000           | mov                 eax, 2
            //   6bc800               | imul                ecx, eax, 0

        $sequence_8 = { 8845ef 0fb64def 51 8b5508 52 e8???????? 83c404 }
            // n = 7, score = 100
            //   8845ef               | mov                 byte ptr [ebp - 0x11], al
            //   0fb64def             | movzx               ecx, byte ptr [ebp - 0x11]
            //   51                   | push                ecx
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_9 = { e8???????? 83c408 89450c 837d0c00 7509 c745f4bc965200 eb06 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   837d0c00             | cmp                 dword ptr [ebp + 0xc], 0
            //   7509                 | jne                 0xb
            //   c745f4bc965200       | mov                 dword ptr [ebp - 0xc], 0x5296bc
            //   eb06                 | jmp                 8

    condition:
        7 of them and filesize < 3080192
}