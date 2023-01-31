rule win_sysget_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.sysget."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sysget"
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
        $sequence_0 = { 75f1 8d85b8f7ffff 8bd0 668b08 83c002 6685c9 }
            // n = 6, score = 400
            //   75f1                 | jne                 0xfffffff3
            //   8d85b8f7ffff         | lea                 eax, [ebp - 0x848]
            //   8bd0                 | mov                 edx, eax
            //   668b08               | mov                 cx, word ptr [eax]
            //   83c002               | add                 eax, 2
            //   6685c9               | test                cx, cx

        $sequence_1 = { f3a5 33f6 8d4435f0 8a08 f6d1 80f15f }
            // n = 6, score = 400
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   33f6                 | xor                 esi, esi
            //   8d4435f0             | lea                 eax, [ebp + esi - 0x10]
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   f6d1                 | not                 cl
            //   80f15f               | xor                 cl, 0x5f

        $sequence_2 = { 743d 8b8538ffffff 40 50 53 56 }
            // n = 6, score = 400
            //   743d                 | je                  0x3f
            //   8b8538ffffff         | mov                 eax, dword ptr [ebp - 0xc8]
            //   40                   | inc                 eax
            //   50                   | push                eax
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_3 = { 8dbdecf1ffff 2bc6 83ef02 668b4f02 83c702 6685c9 75f4 }
            // n = 7, score = 400
            //   8dbdecf1ffff         | lea                 edi, [ebp - 0xe14]
            //   2bc6                 | sub                 eax, esi
            //   83ef02               | sub                 edi, 2
            //   668b4f02             | mov                 cx, word ptr [edi + 2]
            //   83c702               | add                 edi, 2
            //   6685c9               | test                cx, cx
            //   75f4                 | jne                 0xfffffff6

        $sequence_4 = { 56 56 6802140000 ff35???????? ff15???????? 6a6d }
            // n = 6, score = 400
            //   56                   | push                esi
            //   56                   | push                esi
            //   6802140000           | push                0x1402
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   6a6d                 | push                0x6d

        $sequence_5 = { 8d85ecf1ffff 83e103 50 f3a4 }
            // n = 4, score = 400
            //   8d85ecf1ffff         | lea                 eax, [ebp - 0xe14]
            //   83e103               | and                 ecx, 3
            //   50                   | push                eax
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]

        $sequence_6 = { 8d45e4 50 ffd6 85c0 0f84de000000 }
            // n = 5, score = 400
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   0f84de000000         | je                  0xe4

        $sequence_7 = { 85c0 75a7 ff15???????? ebcb }
            // n = 4, score = 400
            //   85c0                 | test                eax, eax
            //   75a7                 | jne                 0xffffffa9
            //   ff15????????         |                     
            //   ebcb                 | jmp                 0xffffffcd

        $sequence_8 = { 8d8decfdffff 03da 668901 0fb703 03ca 83f80a 75f1 }
            // n = 7, score = 400
            //   8d8decfdffff         | lea                 ecx, [ebp - 0x214]
            //   03da                 | add                 ebx, edx
            //   668901               | mov                 word ptr [ecx], ax
            //   0fb703               | movzx               eax, word ptr [ebx]
            //   03ca                 | add                 ecx, edx
            //   83f80a               | cmp                 eax, 0xa
            //   75f1                 | jne                 0xfffffff3

        $sequence_9 = { 3acb 75f9 53 2bc2 50 ff75e8 ff75e0 }
            // n = 7, score = 400
            //   3acb                 | cmp                 cl, bl
            //   75f9                 | jne                 0xfffffffb
            //   53                   | push                ebx
            //   2bc2                 | sub                 eax, edx
            //   50                   | push                eax
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   ff75e0               | push                dword ptr [ebp - 0x20]

    condition:
        7 of them and filesize < 352256
}