rule win_snojan_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.snojan."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.snojan"
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
        $sequence_0 = { 8b4b04 85c9 0f84c3feffff e9???????? 0fb7810000986d 894dc0 }
            // n = 6, score = 200
            //   8b4b04               | mov                 ecx, dword ptr [ebx + 4]
            //   85c9                 | test                ecx, ecx
            //   0f84c3feffff         | je                  0xfffffec9
            //   e9????????           |                     
            //   0fb7810000986d       | movzx               eax, word ptr [ecx + 0x6d980000]
            //   894dc0               | mov                 dword ptr [ebp - 0x40], ecx

        $sequence_1 = { 7e64 89442404 c70424???????? e8???????? 83fd03 7e2f 8d442bfc }
            // n = 7, score = 200
            //   7e64                 | jle                 0x66
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   c70424????????       |                     
            //   e8????????           |                     
            //   83fd03               | cmp                 ebp, 3
            //   7e2f                 | jle                 0x31
            //   8d442bfc             | lea                 eax, [ebx + ebp - 4]

        $sequence_2 = { 89c7 81cf0000ffff 6683b90000986d00 0f48c7 8b7dc4 }
            // n = 5, score = 200
            //   89c7                 | mov                 edi, eax
            //   81cf0000ffff         | or                  edi, 0xffff0000
            //   6683b90000986d00     | cmp                 word ptr [ecx + 0x6d980000], 0
            //   0f48c7               | cmovs               eax, edi
            //   8b7dc4               | mov                 edi, dword ptr [ebp - 0x3c]

        $sequence_3 = { 89c7 b802000000 c70424???????? 6689442420 ff15???????? 83ec04 c70424???????? }
            // n = 7, score = 200
            //   89c7                 | mov                 edi, eax
            //   b802000000           | mov                 eax, 2
            //   c70424????????       |                     
            //   6689442420           | mov                 word ptr [esp + 0x20], ax
            //   ff15????????         |                     
            //   83ec04               | sub                 esp, 4
            //   c70424????????       |                     

        $sequence_4 = { c70424???????? e8???????? 85c0 89c6 0f84bd000000 8d5c2430 }
            // n = 6, score = 200
            //   c70424????????       |                     
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   89c6                 | mov                 esi, eax
            //   0f84bd000000         | je                  0xc3
            //   8d5c2430             | lea                 ebx, [esp + 0x30]

        $sequence_5 = { 893424 e8???????? 893424 e8???????? 807c241f00 0f85b7000000 }
            // n = 6, score = 200
            //   893424               | mov                 dword ptr [esp], esi
            //   e8????????           |                     
            //   893424               | mov                 dword ptr [esp], esi
            //   e8????????           |                     
            //   807c241f00           | cmp                 byte ptr [esp + 0x1f], 0
            //   0f85b7000000         | jne                 0xbd

        $sequence_6 = { c7042402000000 ff15???????? 83ec0c 83f8ff 0f8487010000 }
            // n = 5, score = 200
            //   c7042402000000       | mov                 dword ptr [esp], 2
            //   ff15????????         |                     
            //   83ec0c               | sub                 esp, 0xc
            //   83f8ff               | cmp                 eax, -1
            //   0f8487010000         | je                  0x18d

        $sequence_7 = { a1???????? 8d900000986d 0fb7801400986d 0fb76a06 }
            // n = 4, score = 200
            //   a1????????           |                     
            //   8d900000986d         | lea                 edx, [eax + 0x6d980000]
            //   0fb7801400986d       | movzx               eax, word ptr [eax + 0x6d980014]
            //   0fb76a06             | movzx               ebp, word ptr [edx + 6]

        $sequence_8 = { ff15???????? c70424???????? 89442404 e8???????? ff15???????? }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   c70424????????       |                     
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   e8????????           |                     
            //   ff15????????         |                     

        $sequence_9 = { e8???????? 893424 e8???????? 807c241f00 0f85b7000000 893c24 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   893424               | mov                 dword ptr [esp], esi
            //   e8????????           |                     
            //   807c241f00           | cmp                 byte ptr [esp + 0x1f], 0
            //   0f85b7000000         | jne                 0xbd
            //   893c24               | mov                 dword ptr [esp], edi

    condition:
        7 of them and filesize < 90112
}