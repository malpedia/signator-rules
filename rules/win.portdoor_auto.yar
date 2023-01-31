rule win_portdoor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.portdoor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.portdoor"
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
        $sequence_0 = { b001 5e 5b 5d c20800 32c0 }
            // n = 6, score = 100
            //   b001                 | mov                 al, 1
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c20800               | ret                 8
            //   32c0                 | xor                 al, al

        $sequence_1 = { 899528e5ffff 53 8b1495b80f0210 898d24e5ffff 8a5c1124 02db d0fb }
            // n = 7, score = 100
            //   899528e5ffff         | mov                 dword ptr [ebp - 0x1ad8], edx
            //   53                   | push                ebx
            //   8b1495b80f0210       | mov                 edx, dword ptr [edx*4 + 0x10020fb8]
            //   898d24e5ffff         | mov                 dword ptr [ebp - 0x1adc], ecx
            //   8a5c1124             | mov                 bl, byte ptr [ecx + edx + 0x24]
            //   02db                 | add                 bl, bl
            //   d0fb                 | sar                 bl, 1

        $sequence_2 = { 5f ffb520feffff 660f6f05???????? 8d8560ffffff ffb528feffff f30f7f45e0 }
            // n = 6, score = 100
            //   5f                   | pop                 edi
            //   ffb520feffff         | push                dword ptr [ebp - 0x1e0]
            //   660f6f05????????     |                     
            //   8d8560ffffff         | lea                 eax, [ebp - 0xa0]
            //   ffb528feffff         | push                dword ptr [ebp - 0x1d8]
            //   f30f7f45e0           | movdqu              xmmword ptr [ebp - 0x20], xmm0

        $sequence_3 = { 8b7d08 33db 6a14 8945f4 5e 51 51 }
            // n = 7, score = 100
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   33db                 | xor                 ebx, ebx
            //   6a14                 | push                0x14
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   5e                   | pop                 esi
            //   51                   | push                ecx
            //   51                   | push                ecx

        $sequence_4 = { 83c008 5d c3 8b04c5c4f80110 }
            // n = 4, score = 100
            //   83c008               | add                 eax, 8
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b04c5c4f80110       | mov                 eax, dword ptr [eax*8 + 0x1001f8c4]

        $sequence_5 = { 8d4672 50 8d4652 50 8d85fcfbffff 68???????? 50 }
            // n = 7, score = 100
            //   8d4672               | lea                 eax, [esi + 0x72]
            //   50                   | push                eax
            //   8d4652               | lea                 eax, [esi + 0x52]
            //   50                   | push                eax
            //   8d85fcfbffff         | lea                 eax, [ebp - 0x404]
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_6 = { 53 50 8d85fcf3ffff 50 ff36 }
            // n = 5, score = 100
            //   53                   | push                ebx
            //   50                   | push                eax
            //   8d85fcf3ffff         | lea                 eax, [ebp - 0xc04]
            //   50                   | push                eax
            //   ff36                 | push                dword ptr [esi]

        $sequence_7 = { 83f9ff 745a 57 33ff 8d45f8 }
            // n = 5, score = 100
            //   83f9ff               | cmp                 ecx, -1
            //   745a                 | je                  0x5c
            //   57                   | push                edi
            //   33ff                 | xor                 edi, edi
            //   8d45f8               | lea                 eax, [ebp - 8]

        $sequence_8 = { 33c5 8945fc 53 8b1d???????? 8bcb 56 }
            // n = 6, score = 100
            //   33c5                 | xor                 eax, ebp
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   53                   | push                ebx
            //   8b1d????????         |                     
            //   8bcb                 | mov                 ecx, ebx
            //   56                   | push                esi

        $sequence_9 = { 8bce e8???????? eb11 807e4c00 7409 8bce e8???????? }
            // n = 7, score = 100
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   eb11                 | jmp                 0x13
            //   807e4c00             | cmp                 byte ptr [esi + 0x4c], 0
            //   7409                 | je                  0xb
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

    condition:
        7 of them and filesize < 297984
}