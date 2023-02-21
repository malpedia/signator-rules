rule win_xorist_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.xorist."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xorist"
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
        $sequence_0 = { 0103 83e107 8d4604 894804 0fb7945628050000 eb5d }
            // n = 6, score = 100
            //   0103                 | add                 dword ptr [ebx], eax
            //   83e107               | and                 ecx, 7
            //   8d4604               | lea                 eax, [esi + 4]
            //   894804               | mov                 dword ptr [eax + 4], ecx
            //   0fb7945628050000     | movzx               edx, word ptr [esi + edx*2 + 0x528]
            //   eb5d                 | jmp                 0x5f

        $sequence_1 = { 0103 83e107 894b04 eb03 8d5e04 8bcb }
            // n = 6, score = 100
            //   0103                 | add                 dword ptr [ebx], eax
            //   83e107               | and                 ecx, 7
            //   894b04               | mov                 dword ptr [ebx + 4], ecx
            //   eb03                 | jmp                 5
            //   8d5e04               | lea                 ebx, [esi + 4]
            //   8bcb                 | mov                 ecx, ebx

        $sequence_2 = { 0103 83e107 894b04 0fb78456ec310000 eb5d 6a0f 5f }
            // n = 7, score = 100
            //   0103                 | add                 dword ptr [ebx], eax
            //   83e107               | and                 ecx, 7
            //   894b04               | mov                 dword ptr [ebx + 4], ecx
            //   0fb78456ec310000     | movzx               eax, word ptr [esi + edx*2 + 0x31ec]
            //   eb5d                 | jmp                 0x5f
            //   6a0f                 | push                0xf
            //   5f                   | pop                 edi

        $sequence_3 = { 004701 83be5c06000000 7538 57 55 8bce e8???????? }
            // n = 7, score = 100
            //   004701               | add                 byte ptr [edi + 1], al
            //   83be5c06000000       | cmp                 dword ptr [esi + 0x65c], 0
            //   7538                 | jne                 0x3a
            //   57                   | push                edi
            //   55                   | push                ebp
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_4 = { 0103 2b94bea0000000 6a10 59 2bcf d3ea }
            // n = 6, score = 100
            //   0103                 | add                 dword ptr [ebx], eax
            //   2b94bea0000000       | sub                 edx, dword ptr [esi + edi*4 + 0xa0]
            //   6a10                 | push                0x10
            //   59                   | pop                 ecx
            //   2bcf                 | sub                 ecx, edi
            //   d3ea                 | shr                 edx, cl

        $sequence_5 = { 0101 895104 c20400 e9???????? }
            // n = 4, score = 100
            //   0101                 | add                 dword ptr [ecx], eax
            //   895104               | mov                 dword ptr [ecx + 4], edx
            //   c20400               | ret                 4
            //   e9????????           |                     

        $sequence_6 = { 0102 83e107 894a04 eb03 8d5704 8bca e8???????? }
            // n = 7, score = 100
            //   0102                 | add                 dword ptr [edx], eax
            //   83e107               | and                 ecx, 7
            //   894a04               | mov                 dword ptr [edx + 4], ecx
            //   eb03                 | jmp                 5
            //   8d5704               | lea                 edx, [edi + 4]
            //   8bca                 | mov                 ecx, edx
            //   e8????????           |                     

        $sequence_7 = { 00042f 00442f02 83c703 3bf9 72ee e9???????? }
            // n = 6, score = 100
            //   00042f               | add                 byte ptr [edi + ebp], al
            //   00442f02             | add                 byte ptr [edi + ebp + 2], al
            //   83c703               | add                 edi, 3
            //   3bf9                 | cmp                 edi, ecx
            //   72ee                 | jb                  0xfffffff0
            //   e9????????           |                     

    condition:
        7 of them and filesize < 1402880
}