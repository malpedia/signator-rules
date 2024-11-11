rule win_ondritols_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.ondritols."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ondritols"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
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
        $sequence_0 = { 8b4de0 0b0d???????? 894de0 8b550c 83c201 89550c 8b450c }
            // n = 7, score = 100
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   0b0d????????         |                     
            //   894de0               | mov                 dword ptr [ebp - 0x20], ecx
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   83c201               | add                 edx, 1
            //   89550c               | mov                 dword ptr [ebp + 0xc], edx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_1 = { 8b4d08 e8???????? 85c0 7514 3bf7 7309 5f }
            // n = 7, score = 100
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7514                 | jne                 0x16
            //   3bf7                 | cmp                 esi, edi
            //   7309                 | jae                 0xb
            //   5f                   | pop                 edi

        $sequence_2 = { e8???????? 83c410 c644241301 3bd8 7505 c644241300 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   c644241301           | mov                 byte ptr [esp + 0x13], 1
            //   3bd8                 | cmp                 ebx, eax
            //   7505                 | jne                 7
            //   c644241300           | mov                 byte ptr [esp + 0x13], 0

        $sequence_3 = { 0fbe11 83fa5d 7513 8d45d4 50 8b4de8 }
            // n = 6, score = 100
            //   0fbe11               | movsx               edx, byte ptr [ecx]
            //   83fa5d               | cmp                 edx, 0x5d
            //   7513                 | jne                 0x15
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   50                   | push                eax
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]

        $sequence_4 = { 85c0 0f8493000000 6853040000 68???????? 8b45e0 50 e8???????? }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   0f8493000000         | je                  0x99
            //   6853040000           | push                0x453
            //   68????????           |                     
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_5 = { 68???????? e8???????? 2bc1 8b4d10 3bc1 7305 894510 }
            // n = 7, score = 100
            //   68????????           |                     
            //   e8????????           |                     
            //   2bc1                 | sub                 eax, ecx
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   3bc1                 | cmp                 eax, ecx
            //   7305                 | jae                 7
            //   894510               | mov                 dword ptr [ebp + 0x10], eax

        $sequence_6 = { 8b5d08 56 8bf1 8b4614 83c9ff 2bc8 3bcb }
            // n = 7, score = 100
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   8b4614               | mov                 eax, dword ptr [esi + 0x14]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   2bc8                 | sub                 ecx, eax
            //   3bcb                 | cmp                 ecx, ebx

        $sequence_7 = { 8b4dec e8???????? 898594feffff 8b8d94feffff 898d90feffff c645fc02 8b8d90feffff }
            // n = 7, score = 100
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   e8????????           |                     
            //   898594feffff         | mov                 dword ptr [ebp - 0x16c], eax
            //   8b8d94feffff         | mov                 ecx, dword ptr [ebp - 0x16c]
            //   898d90feffff         | mov                 dword ptr [ebp - 0x170], ecx
            //   c645fc02             | mov                 byte ptr [ebp - 4], 2
            //   8b8d90feffff         | mov                 ecx, dword ptr [ebp - 0x170]

        $sequence_8 = { 83e01f c1e006 8b0c95e0ca4600 833c08ff 7468 833d????????01 753c }
            // n = 7, score = 100
            //   83e01f               | and                 eax, 0x1f
            //   c1e006               | shl                 eax, 6
            //   8b0c95e0ca4600       | mov                 ecx, dword ptr [edx*4 + 0x46cae0]
            //   833c08ff             | cmp                 dword ptr [eax + ecx], -1
            //   7468                 | je                  0x6a
            //   833d????????01       |                     
            //   753c                 | jne                 0x3e

        $sequence_9 = { 8d8d1fffffff 51 8b4d08 e8???????? 50 8b4de8 e8???????? }
            // n = 7, score = 100
            //   8d8d1fffffff         | lea                 ecx, [ebp - 0xe1]
            //   51                   | push                ecx
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   e8????????           |                     
            //   50                   | push                eax
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   e8????????           |                     

    condition:
        7 of them and filesize < 964608
}