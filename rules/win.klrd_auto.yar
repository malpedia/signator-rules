rule win_klrd_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.klrd."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.klrd"
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
        $sequence_0 = { 59 59 eb12 ffb5c8feffff ff15???????? 8985bcfdffff }
            // n = 6, score = 100
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   eb12                 | jmp                 0x14
            //   ffb5c8feffff         | push                dword ptr [ebp - 0x138]
            //   ff15????????         |                     
            //   8985bcfdffff         | mov                 dword ptr [ebp - 0x244], eax

        $sequence_1 = { 59 ff7510 ff750c ff7508 ff35???????? ff15???????? 5f }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   5f                   | pop                 edi

        $sequence_2 = { 59 eb66 68???????? e8???????? }
            // n = 4, score = 100
            //   59                   | pop                 ecx
            //   eb66                 | jmp                 0x68
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_3 = { ffb5bcfdffff 6a01 8d85c4feffff 50 8d85c0fdffff }
            // n = 5, score = 100
            //   ffb5bcfdffff         | push                dword ptr [ebp - 0x244]
            //   6a01                 | push                1
            //   8d85c4feffff         | lea                 eax, [ebp - 0x13c]
            //   50                   | push                eax
            //   8d85c0fdffff         | lea                 eax, [ebp - 0x240]

        $sequence_4 = { 83c40c 83a5b0fcffff00 83a5bcfdffff00 33c0 668985c4feffff 837d0800 }
            // n = 6, score = 100
            //   83c40c               | add                 esp, 0xc
            //   83a5b0fcffff00       | and                 dword ptr [ebp - 0x350], 0
            //   83a5bcfdffff00       | and                 dword ptr [ebp - 0x244], 0
            //   33c0                 | xor                 eax, eax
            //   668985c4feffff       | mov                 word ptr [ebp - 0x13c], ax
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0

        $sequence_5 = { 50 68???????? 6a0d ff15???????? a3???????? e8???????? ff35???????? }
            // n = 7, score = 100
            //   50                   | push                eax
            //   68????????           |                     
            //   6a0d                 | push                0xd
            //   ff15????????         |                     
            //   a3????????           |                     
            //   e8????????           |                     
            //   ff35????????         |                     

        $sequence_6 = { 8985c8feffff 83bdc8feffff00 7515 ff15???????? 50 }
            // n = 5, score = 100
            //   8985c8feffff         | mov                 dword ptr [ebp - 0x138], eax
            //   83bdc8feffff00       | cmp                 dword ptr [ebp - 0x138], 0
            //   7515                 | jne                 0x17
            //   ff15????????         |                     
            //   50                   | push                eax

        $sequence_7 = { 68ff000000 6a00 8d85b9fcffff 50 e8???????? 83c40c c685e8feffff00 }
            // n = 7, score = 100
            //   68ff000000           | push                0xff
            //   6a00                 | push                0
            //   8d85b9fcffff         | lea                 eax, [ebp - 0x347]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   c685e8feffff00       | mov                 byte ptr [ebp - 0x118], 0

        $sequence_8 = { 8d85e8feffff 50 ffb5b0fcffff ff15???????? 85c0 7515 }
            // n = 6, score = 100
            //   8d85e8feffff         | lea                 eax, [ebp - 0x118]
            //   50                   | push                eax
            //   ffb5b0fcffff         | push                dword ptr [ebp - 0x350]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7515                 | jne                 0x17

        $sequence_9 = { 40 8985d0feffff 81bdd0feffff00010000 7d1b ffb5d0feffff ff15???????? }
            // n = 6, score = 100
            //   40                   | inc                 eax
            //   8985d0feffff         | mov                 dword ptr [ebp - 0x130], eax
            //   81bdd0feffff00010000     | cmp    dword ptr [ebp - 0x130], 0x100
            //   7d1b                 | jge                 0x1d
            //   ffb5d0feffff         | push                dword ptr [ebp - 0x130]
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 40960
}