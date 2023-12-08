rule win_uacme_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.uacme."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.uacme"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
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
        $sequence_0 = { ba???????? e8???????? 8d8df0fbffff e8???????? 8bf8 85ff 741b }
            // n = 7, score = 100
            //   ba????????           |                     
            //   e8????????           |                     
            //   8d8df0fbffff         | lea                 ecx, [ebp - 0x410]
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi
            //   741b                 | je                  0x1d

        $sequence_1 = { ff9620060000 33c0 5e 8be5 5d c20400 }
            // n = 6, score = 100
            //   ff9620060000         | call                dword ptr [esi + 0x620]
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4

        $sequence_2 = { eb23 8b4d08 e8???????? 03c0 }
            // n = 4, score = 100
            //   eb23                 | jmp                 0x25
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   e8????????           |                     
            //   03c0                 | add                 eax, eax

        $sequence_3 = { 8d45d8 50 6804900000 56 ff15???????? 6808700000 56 }
            // n = 7, score = 100
            //   8d45d8               | lea                 eax, [ebp - 0x28]
            //   50                   | push                eax
            //   6804900000           | push                0x9004
            //   56                   | push                esi
            //   ff15????????         |                     
            //   6808700000           | push                0x7008
            //   56                   | push                esi

        $sequence_4 = { ba???????? 8d8940040000 e8???????? 8b45fc ff7010 ffd6 }
            // n = 6, score = 100
            //   ba????????           |                     
            //   8d8940040000         | lea                 ecx, [ecx + 0x440]
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   ff7010               | push                dword ptr [eax + 0x10]
            //   ffd6                 | call                esi

        $sequence_5 = { 8bd8 85db 74d3 8b5508 8bcb e8???????? }
            // n = 6, score = 100
            //   8bd8                 | mov                 ebx, eax
            //   85db                 | test                ebx, ebx
            //   74d3                 | je                  0xffffffd5
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     

        $sequence_6 = { 668974242e ff15???????? 85c0 0f88c9040000 ff15???????? b940040000 }
            // n = 6, score = 100
            //   668974242e           | mov                 word ptr [esp + 0x2e], si
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f88c9040000         | js                  0x4cf
            //   ff15????????         |                     
            //   b940040000           | mov                 ecx, 0x440

        $sequence_7 = { e8???????? 8bce 8d85e0fbffff 8818 40 83e901 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8bce                 | mov                 ecx, esi
            //   8d85e0fbffff         | lea                 eax, [ebp - 0x420]
            //   8818                 | mov                 byte ptr [eax], bl
            //   40                   | inc                 eax
            //   83e901               | sub                 ecx, 1

        $sequence_8 = { b9???????? e8???????? 6683bdf0fbffff00 8bf0 740d 8d85f0fbffff 50 }
            // n = 7, score = 100
            //   b9????????           |                     
            //   e8????????           |                     
            //   6683bdf0fbffff00     | cmp                 word ptr [ebp - 0x410], 0
            //   8bf0                 | mov                 esi, eax
            //   740d                 | je                  0xf
            //   8d85f0fbffff         | lea                 eax, [ebp - 0x410]
            //   50                   | push                eax

        $sequence_9 = { 8d85f0fbffff 50 8d85e0f7ffff 50 e8???????? 8bd8 }
            // n = 6, score = 100
            //   8d85f0fbffff         | lea                 eax, [ebp - 0x410]
            //   50                   | push                eax
            //   8d85e0f7ffff         | lea                 eax, [ebp - 0x820]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax

    condition:
        7 of them and filesize < 565248
}