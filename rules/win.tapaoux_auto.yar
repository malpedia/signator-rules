rule win_tapaoux_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.tapaoux."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tapaoux"
        malpedia_rule_date = "20211007"
        malpedia_hash = "e5b790e0f888f252d49063a1251ca60ec2832535"
        malpedia_version = "20211008"
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
        $sequence_0 = { f3a4 33ff 85ed 7e3d 8b9c2498000000 8bf2 2bda }
            // n = 7, score = 200
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   33ff                 | xor                 edi, edi
            //   85ed                 | test                ebp, ebp
            //   7e3d                 | jle                 0x3f
            //   8b9c2498000000       | mov                 ebx, dword ptr [esp + 0x98]
            //   8bf2                 | mov                 esi, edx
            //   2bda                 | sub                 ebx, edx

        $sequence_1 = { 33c0 8d7c2415 c644241400 8b942460010000 f3ab 66ab }
            // n = 6, score = 200
            //   33c0                 | xor                 eax, eax
            //   8d7c2415             | lea                 edi, dword ptr [esp + 0x15]
            //   c644241400           | mov                 byte ptr [esp + 0x14], 0
            //   8b942460010000       | mov                 edx, dword ptr [esp + 0x160]
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax

        $sequence_2 = { 52 57 e8???????? 85c0 744e 8d442418 53 }
            // n = 7, score = 200
            //   52                   | push                edx
            //   57                   | push                edi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   744e                 | je                  0x50
            //   8d442418             | lea                 eax, dword ptr [esp + 0x18]
            //   53                   | push                ebx

        $sequence_3 = { ff15???????? 8b84241c030000 8d4c2400 50 51 8d942408010000 }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   8b84241c030000       | mov                 eax, dword ptr [esp + 0x31c]
            //   8d4c2400             | lea                 ecx, dword ptr [esp]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   8d942408010000       | lea                 edx, dword ptr [esp + 0x108]

        $sequence_4 = { 8d442408 55 50 8d8c241c040000 6800040000 51 }
            // n = 6, score = 200
            //   8d442408             | lea                 eax, dword ptr [esp + 8]
            //   55                   | push                ebp
            //   50                   | push                eax
            //   8d8c241c040000       | lea                 ecx, dword ptr [esp + 0x41c]
            //   6800040000           | push                0x400
            //   51                   | push                ecx

        $sequence_5 = { e8???????? bf???????? 83c9ff 33c0 83c43c f2ae f7d1 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   bf????????           |                     
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   83c43c               | add                 esp, 0x3c
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx

        $sequence_6 = { 4f c1e902 f3a5 8bca b801000000 83e103 }
            // n = 6, score = 200
            //   4f                   | dec                 edi
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bca                 | mov                 ecx, edx
            //   b801000000           | mov                 eax, 1
            //   83e103               | and                 ecx, 3

        $sequence_7 = { 689d130000 a3???????? e8???????? 8b0d???????? 83c40c 85c9 a3???????? }
            // n = 7, score = 200
            //   689d130000           | push                0x139d
            //   a3????????           |                     
            //   e8????????           |                     
            //   8b0d????????         |                     
            //   83c40c               | add                 esp, 0xc
            //   85c9                 | test                ecx, ecx
            //   a3????????           |                     

        $sequence_8 = { 803939 0f8fedfeffff 8a4101 41 3ac3 75e7 8d442410 }
            // n = 7, score = 200
            //   803939               | cmp                 byte ptr [ecx], 0x39
            //   0f8fedfeffff         | jg                  0xfffffef3
            //   8a4101               | mov                 al, byte ptr [ecx + 1]
            //   41                   | inc                 ecx
            //   3ac3                 | cmp                 al, bl
            //   75e7                 | jne                 0xffffffe9
            //   8d442410             | lea                 eax, dword ptr [esp + 0x10]

        $sequence_9 = { 83c8ff 5b 81c400010000 c3 8b0d???????? }
            // n = 5, score = 200
            //   83c8ff               | or                  eax, 0xffffffff
            //   5b                   | pop                 ebx
            //   81c400010000         | add                 esp, 0x100
            //   c3                   | ret                 
            //   8b0d????????         |                     

    condition:
        7 of them and filesize < 294912
}