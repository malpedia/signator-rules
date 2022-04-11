rule win_getmypass_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.getmypass."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.getmypass"
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
        $sequence_0 = { 8b45f4 8902 8b4d08 8b55f8 895104 33c0 8be5 }
            // n = 7, score = 200
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8902                 | mov                 dword ptr [edx], eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   895104               | mov                 dword ptr [ecx + 4], edx
            //   33c0                 | xor                 eax, eax
            //   8be5                 | mov                 esp, ebp

        $sequence_1 = { 52 8b45a8 50 8b4de4 51 8b55e0 52 }
            // n = 7, score = 200
            //   52                   | push                edx
            //   8b45a8               | mov                 eax, dword ptr [ebp - 0x58]
            //   50                   | push                eax
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]
            //   51                   | push                ecx
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]
            //   52                   | push                edx

        $sequence_2 = { 6800300000 6800500600 6a00 ff15???????? 8985a0fdffff 6a00 }
            // n = 6, score = 200
            //   6800300000           | push                0x3000
            //   6800500600           | push                0x65000
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8985a0fdffff         | mov                 dword ptr [ebp - 0x260], eax
            //   6a00                 | push                0

        $sequence_3 = { 68???????? 8b15???????? 52 e8???????? 83c408 8b4508 83c040 }
            // n = 7, score = 200
            //   68????????           |                     
            //   8b15????????         |                     
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83c040               | add                 eax, 0x40

        $sequence_4 = { 83c201 8955fc ebcb 837dfc05 }
            // n = 4, score = 200
            //   83c201               | add                 edx, 1
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   ebcb                 | jmp                 0xffffffcd
            //   837dfc05             | cmp                 dword ptr [ebp - 4], 5

        $sequence_5 = { 8b4dfc 83c101 894dfc ebcb 32c0 8be5 }
            // n = 6, score = 200
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   83c101               | add                 ecx, 1
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   ebcb                 | jmp                 0xffffffcd
            //   32c0                 | xor                 al, al
            //   8be5                 | mov                 esp, ebp

        $sequence_6 = { 8b95a8fdffff 52 e8???????? 8d85f4fdffff 50 e8???????? 83c404 }
            // n = 7, score = 200
            //   8b95a8fdffff         | mov                 edx, dword ptr [ebp - 0x258]
            //   52                   | push                edx
            //   e8????????           |                     
            //   8d85f4fdffff         | lea                 eax, dword ptr [ebp - 0x20c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_7 = { 8995ecfeffff 83bdecfeffff0a 7d1d 8b85ecfeffff }
            // n = 4, score = 200
            //   8995ecfeffff         | mov                 dword ptr [ebp - 0x114], edx
            //   83bdecfeffff0a       | cmp                 dword ptr [ebp - 0x114], 0xa
            //   7d1d                 | jge                 0x1f
            //   8b85ecfeffff         | mov                 eax, dword ptr [ebp - 0x114]

        $sequence_8 = { 50 e8???????? 83c408 6a1c 8d8db0fdffff }
            // n = 5, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   6a1c                 | push                0x1c
            //   8d8db0fdffff         | lea                 ecx, dword ptr [ebp - 0x250]

        $sequence_9 = { 8b4df4 83c101 81e1ff000000 894df4 }
            // n = 4, score = 200
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   83c101               | add                 ecx, 1
            //   81e1ff000000         | and                 ecx, 0xff
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx

    condition:
        7 of them and filesize < 49152
}