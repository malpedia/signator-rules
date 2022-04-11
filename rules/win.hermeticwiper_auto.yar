rule win_hermeticwiper_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.hermeticwiper."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hermeticwiper"
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
        $sequence_0 = { 5d c20400 8b7708 85f6 74eb ff770c }
            // n = 6, score = 200
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   8b7708               | mov                 esi, dword ptr [edi + 8]
            //   85f6                 | test                esi, esi
            //   74eb                 | je                  0xffffffed
            //   ff770c               | push                dword ptr [edi + 0xc]

        $sequence_1 = { 68???????? 6a00 ff15???????? 8945f8 85c0 7514 ffd6 }
            // n = 7, score = 200
            //   68????????           |                     
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   85c0                 | test                eax, eax
            //   7514                 | jne                 0x16
            //   ffd6                 | call                esi

        $sequence_2 = { 8b3d???????? 53 ffd7 53 ff15???????? 85c0 7408 }
            // n = 7, score = 200
            //   8b3d????????         |                     
            //   53                   | push                ebx
            //   ffd7                 | call                edi
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7408                 | je                  0xa

        $sequence_3 = { 83c410 8d8d60f9ffff 33d2 6a00 e8???????? 85c0 7418 }
            // n = 7, score = 200
            //   83c410               | add                 esp, 0x10
            //   8d8d60f9ffff         | lea                 ecx, dword ptr [ebp - 0x6a0]
            //   33d2                 | xor                 edx, edx
            //   6a00                 | push                0
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7418                 | je                  0x1a

        $sequence_4 = { 6a00 6a00 8d442424 50 68???????? 6a00 6a00 }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d442424             | lea                 eax, dword ptr [esp + 0x24]
            //   50                   | push                eax
            //   68????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_5 = { 6685c0 75f0 33ff 8b74bdf8 53 ff15???????? 03c0 }
            // n = 7, score = 200
            //   6685c0               | test                ax, ax
            //   75f0                 | jne                 0xfffffff2
            //   33ff                 | xor                 edi, edi
            //   8b74bdf8             | mov                 esi, dword ptr [ebp + edi*4 - 8]
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   03c0                 | add                 eax, eax

        $sequence_6 = { 6a00 6a00 8d45e8 c745e8ff000000 50 8d85e8fdffff }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d45e8               | lea                 eax, dword ptr [ebp - 0x18]
            //   c745e8ff000000       | mov                 dword ptr [ebp - 0x18], 0xff
            //   50                   | push                eax
            //   8d85e8fdffff         | lea                 eax, dword ptr [ebp - 0x218]

        $sequence_7 = { 50 6803000080 ffd7 85c0 7552 8945fc 8d45fc }
            // n = 7, score = 200
            //   50                   | push                eax
            //   6803000080           | push                0x80000003
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax
            //   7552                 | jne                 0x54
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8d45fc               | lea                 eax, dword ptr [ebp - 4]

        $sequence_8 = { ff15???????? 8bf8 897de8 85ff 0f84c1000000 8b45f8 6a00 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   897de8               | mov                 dword ptr [ebp - 0x18], edi
            //   85ff                 | test                edi, edi
            //   0f84c1000000         | je                  0xc7
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   6a00                 | push                0

        $sequence_9 = { 7205 3b4dfc 7710 8b4d0c 3bd9 7779 7207 }
            // n = 7, score = 200
            //   7205                 | jb                  7
            //   3b4dfc               | cmp                 ecx, dword ptr [ebp - 4]
            //   7710                 | ja                  0x12
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   3bd9                 | cmp                 ebx, ecx
            //   7779                 | ja                  0x7b
            //   7207                 | jb                  9

    condition:
        7 of them and filesize < 247808
}