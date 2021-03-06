rule win_tandfuy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.tandfuy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tandfuy"
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
        $sequence_0 = { 83c438 83f801 0f85bf020000 8dbdecfdffff 83c9ff 33c0 }
            // n = 6, score = 100
            //   83c438               | add                 esp, 0x38
            //   83f801               | cmp                 eax, 1
            //   0f85bf020000         | jne                 0x2c5
            //   8dbdecfdffff         | lea                 edi, [ebp - 0x214]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax

        $sequence_1 = { 53 56 8bb424102c0000 57 }
            // n = 4, score = 100
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8bb424102c0000       | mov                 esi, dword ptr [esp + 0x2c10]
            //   57                   | push                edi

        $sequence_2 = { ff15???????? 8b442438 5b 25ff000000 5e }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   8b442438             | mov                 eax, dword ptr [esp + 0x38]
            //   5b                   | pop                 ebx
            //   25ff000000           | and                 eax, 0xff
            //   5e                   | pop                 esi

        $sequence_3 = { 8a9405ecfcffff ebe3 80a020ea6e0000 40 41 41 }
            // n = 6, score = 100
            //   8a9405ecfcffff       | mov                 dl, byte ptr [ebp + eax - 0x314]
            //   ebe3                 | jmp                 0xffffffe5
            //   80a020ea6e0000       | and                 byte ptr [eax + 0x6eea20], 0
            //   40                   | inc                 eax
            //   41                   | inc                 ecx
            //   41                   | inc                 ecx

        $sequence_4 = { 731f 8bc8 83e01f c1f905 8d04c0 8b0c8d60fc6e00 f644810401 }
            // n = 7, score = 100
            //   731f                 | jae                 0x21
            //   8bc8                 | mov                 ecx, eax
            //   83e01f               | and                 eax, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   8d04c0               | lea                 eax, [eax + eax*8]
            //   8b0c8d60fc6e00       | mov                 ecx, dword ptr [ecx*4 + 0x6efc60]
            //   f644810401           | test                byte ptr [ecx + eax*4 + 4], 1

        $sequence_5 = { 88542440 e8???????? 84c0 88442408 }
            // n = 4, score = 100
            //   88542440             | mov                 byte ptr [esp + 0x40], dl
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   88442408             | mov                 byte ptr [esp + 8], al

        $sequence_6 = { 8d85d8f5ffff 50 e8???????? 68e8030000 ff15???????? 8d8dd8f5ffff }
            // n = 6, score = 100
            //   8d85d8f5ffff         | lea                 eax, [ebp - 0xa28]
            //   50                   | push                eax
            //   e8????????           |                     
            //   68e8030000           | push                0x3e8
            //   ff15????????         |                     
            //   8d8dd8f5ffff         | lea                 ecx, [ebp - 0xa28]

        $sequence_7 = { 8a5002 52 33c9 8a4801 51 33d2 }
            // n = 6, score = 100
            //   8a5002               | mov                 dl, byte ptr [eax + 2]
            //   52                   | push                edx
            //   33c9                 | xor                 ecx, ecx
            //   8a4801               | mov                 cl, byte ptr [eax + 1]
            //   51                   | push                ecx
            //   33d2                 | xor                 edx, edx

        $sequence_8 = { 50 68???????? 8d8decfdffff 51 e8???????? 83c40c }
            // n = 6, score = 100
            //   50                   | push                eax
            //   68????????           |                     
            //   8d8decfdffff         | lea                 ecx, [ebp - 0x214]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_9 = { e8???????? 83c418 8bd0 8995d4faffff }
            // n = 4, score = 100
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   8bd0                 | mov                 edx, eax
            //   8995d4faffff         | mov                 dword ptr [ebp - 0x52c], edx

    condition:
        7 of them and filesize < 155648
}