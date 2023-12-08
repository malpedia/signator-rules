rule win_sneepy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.sneepy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sneepy"
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
        $sequence_0 = { e8???????? 83c40c 33c0 8a8810234100 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   33c0                 | xor                 eax, eax
            //   8a8810234100         | mov                 cl, byte ptr [eax + 0x412310]

        $sequence_1 = { 83f8ff 0f85abfeffff 5f 5e }
            // n = 4, score = 100
            //   83f8ff               | cmp                 eax, -1
            //   0f85abfeffff         | jne                 0xfffffeb1
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_2 = { 8945e4 8845e8 e8???????? 8d55e4 83c404 2bd0 8a08 }
            // n = 7, score = 100
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8845e8               | mov                 byte ptr [ebp - 0x18], al
            //   e8????????           |                     
            //   8d55e4               | lea                 edx, [ebp - 0x1c]
            //   83c404               | add                 esp, 4
            //   2bd0                 | sub                 edx, eax
            //   8a08                 | mov                 cl, byte ptr [eax]

        $sequence_3 = { ffd6 85c0 740d 8b85b8feffff 50 ffd6 }
            // n = 6, score = 100
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   740d                 | je                  0xf
            //   8b85b8feffff         | mov                 eax, dword ptr [ebp - 0x148]
            //   50                   | push                eax
            //   ffd6                 | call                esi

        $sequence_4 = { e8???????? 83c40c 32c0 5e 8b4dfc }
            // n = 5, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   32c0                 | xor                 al, al
            //   5e                   | pop                 esi
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_5 = { 68???????? 8945f4 8845f8 e8???????? 8d55f4 83c404 }
            // n = 6, score = 100
            //   68????????           |                     
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8845f8               | mov                 byte ptr [ebp - 8], al
            //   e8????????           |                     
            //   8d55f4               | lea                 edx, [ebp - 0xc]
            //   83c404               | add                 esp, 4

        $sequence_6 = { ff15???????? 8bc8 8a10 40 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   8bc8                 | mov                 ecx, eax
            //   8a10                 | mov                 dl, byte ptr [eax]
            //   40                   | inc                 eax

        $sequence_7 = { 33c0 8b4d08 3b0cc520de4000 740a 40 83f816 72ee }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   3b0cc520de4000       | cmp                 ecx, dword ptr [eax*8 + 0x40de20]
            //   740a                 | je                  0xc
            //   40                   | inc                 eax
            //   83f816               | cmp                 eax, 0x16
            //   72ee                 | jb                  0xfffffff0

        $sequence_8 = { 668b0d???????? 8a15???????? 668908 6a50 }
            // n = 4, score = 100
            //   668b0d????????       |                     
            //   8a15????????         |                     
            //   668908               | mov                 word ptr [eax], cx
            //   6a50                 | push                0x50

        $sequence_9 = { 33c0 8945e4 83f805 7d10 668b4c4310 66890c4514314100 }
            // n = 6, score = 100
            //   33c0                 | xor                 eax, eax
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   83f805               | cmp                 eax, 5
            //   7d10                 | jge                 0x12
            //   668b4c4310           | mov                 cx, word ptr [ebx + eax*2 + 0x10]
            //   66890c4514314100     | mov                 word ptr [eax*2 + 0x413114], cx

    condition:
        7 of them and filesize < 188416
}