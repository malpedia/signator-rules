rule win_lokipws_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.lokipws."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lokipws"
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
        $sequence_0 = { 6a00 57 68???????? 68???????? 56 e8???????? 83c418 }
            // n = 7, score = 300
            //   6a00                 | push                0
            //   57                   | push                edi
            //   68????????           |                     
            //   68????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18

        $sequence_1 = { ff7508 8975fc e8???????? 8bf8 59 59 85ff }
            // n = 7, score = 300
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85ff                 | test                edi, edi

        $sequence_2 = { 59 53 ff75f8 e8???????? 59 59 }
            // n = 6, score = 300
            //   59                   | pop                 ecx
            //   53                   | push                ebx
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx

        $sequence_3 = { 8d85e4fdffff 50 e8???????? 6880030000 ffb548feffff 8d8564faffff ffb544feffff }
            // n = 7, score = 300
            //   8d85e4fdffff         | lea                 eax, dword ptr [ebp - 0x21c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   6880030000           | push                0x380
            //   ffb548feffff         | push                dword ptr [ebp - 0x1b8]
            //   8d8564faffff         | lea                 eax, dword ptr [ebp - 0x59c]
            //   ffb544feffff         | push                dword ptr [ebp - 0x1bc]

        $sequence_4 = { 8d8560ffffff c745f801000000 50 8d45c0 50 e8???????? 8bd8 }
            // n = 7, score = 300
            //   8d8560ffffff         | lea                 eax, dword ptr [ebp - 0xa0]
            //   c745f801000000       | mov                 dword ptr [ebp - 8], 1
            //   50                   | push                eax
            //   8d45c0               | lea                 eax, dword ptr [ebp - 0x40]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax

        $sequence_5 = { 8b85e4f4ffff 50 e8???????? 53 e8???????? 59 59 }
            // n = 7, score = 300
            //   8b85e4f4ffff         | mov                 eax, dword ptr [ebp - 0xb1c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   53                   | push                ebx
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx

        $sequence_6 = { 8d8df0fdffff 51 ffd0 57 57 68994b5ddc 6a06 }
            // n = 7, score = 300
            //   8d8df0fdffff         | lea                 ecx, dword ptr [ebp - 0x210]
            //   51                   | push                ecx
            //   ffd0                 | call                eax
            //   57                   | push                edi
            //   57                   | push                edi
            //   68994b5ddc           | push                0xdc5d4b99
            //   6a06                 | push                6

        $sequence_7 = { 6a5c 668945d0 58 6a4e 668945d6 66894dc0 66894dce }
            // n = 7, score = 300
            //   6a5c                 | push                0x5c
            //   668945d0             | mov                 word ptr [ebp - 0x30], ax
            //   58                   | pop                 eax
            //   6a4e                 | push                0x4e
            //   668945d6             | mov                 word ptr [ebp - 0x2a], ax
            //   66894dc0             | mov                 word ptr [ebp - 0x40], cx
            //   66894dce             | mov                 word ptr [ebp - 0x32], cx

        $sequence_8 = { e8???????? 59 85c0 757e 56 e8???????? ff750c }
            // n = 7, score = 300
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   757e                 | jne                 0x80
            //   56                   | push                esi
            //   e8????????           |                     
            //   ff750c               | push                dword ptr [ebp + 0xc]

        $sequence_9 = { 66894588 66899d5cffffff 66898d66ffffff 66898d6effffff 66898d76ffffff 6689bd78ffffff 66899d7affffff }
            // n = 7, score = 300
            //   66894588             | mov                 word ptr [ebp - 0x78], ax
            //   66899d5cffffff       | mov                 word ptr [ebp - 0xa4], bx
            //   66898d66ffffff       | mov                 word ptr [ebp - 0x9a], cx
            //   66898d6effffff       | mov                 word ptr [ebp - 0x92], cx
            //   66898d76ffffff       | mov                 word ptr [ebp - 0x8a], cx
            //   6689bd78ffffff       | mov                 word ptr [ebp - 0x88], di
            //   66899d7affffff       | mov                 word ptr [ebp - 0x86], bx

    condition:
        7 of them and filesize < 1327104
}