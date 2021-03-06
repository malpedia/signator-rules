rule win_himan_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.himan."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.himan"
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
        $sequence_0 = { 333cadbcbe6e00 8beb c1ed10 81e5ff000000 81e1ff000000 c1eb18 333cadbcc26e00 }
            // n = 7, score = 100
            //   333cadbcbe6e00       | xor                 edi, dword ptr [ebp*4 + 0x6ebebc]
            //   8beb                 | mov                 ebp, ebx
            //   c1ed10               | shr                 ebp, 0x10
            //   81e5ff000000         | and                 ebp, 0xff
            //   81e1ff000000         | and                 ecx, 0xff
            //   c1eb18               | shr                 ebx, 0x18
            //   333cadbcc26e00       | xor                 edi, dword ptr [ebp*4 + 0x6ec2bc]

        $sequence_1 = { 894720 8d4f24 8bd0 83c604 c1ca08 8bda 8bc2 }
            // n = 7, score = 100
            //   894720               | mov                 dword ptr [edi + 0x20], eax
            //   8d4f24               | lea                 ecx, [edi + 0x24]
            //   8bd0                 | mov                 edx, eax
            //   83c604               | add                 esi, 4
            //   c1ca08               | ror                 edx, 8
            //   8bda                 | mov                 ebx, edx
            //   8bc2                 | mov                 eax, edx

        $sequence_2 = { ff15???????? 85db 7504 33f6 eb2f 53 ff15???????? }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   85db                 | test                ebx, ebx
            //   7504                 | jne                 6
            //   33f6                 | xor                 esi, esi
            //   eb2f                 | jmp                 0x31
            //   53                   | push                ebx
            //   ff15????????         |                     

        $sequence_3 = { 3322 333433 51 335833 6c 337e33 94 }
            // n = 7, score = 100
            //   3322                 | xor                 esp, dword ptr [edx]
            //   333433               | xor                 esi, dword ptr [ebx + esi]
            //   51                   | push                ecx
            //   335833               | xor                 ebx, dword ptr [eax + 0x33]
            //   6c                   | insb                byte ptr es:[edi], dx
            //   337e33               | xor                 edi, dword ptr [esi + 0x33]
            //   94                   | xchg                eax, esp

        $sequence_4 = { 8b3cbdbcbe6e00 c1ee18 33fd 8b2cb5bcc66e00 8b742430 81e6ff000000 33fd }
            // n = 7, score = 100
            //   8b3cbdbcbe6e00       | mov                 edi, dword ptr [edi*4 + 0x6ebebc]
            //   c1ee18               | shr                 esi, 0x18
            //   33fd                 | xor                 edi, ebp
            //   8b2cb5bcc66e00       | mov                 ebp, dword ptr [esi*4 + 0x6ec6bc]
            //   8b742430             | mov                 esi, dword ptr [esp + 0x30]
            //   81e6ff000000         | and                 esi, 0xff
            //   33fd                 | xor                 edi, ebp

        $sequence_5 = { e8???????? 83c408 83fb01 884701 7e20 8bc6 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   83fb01               | cmp                 ebx, 1
            //   884701               | mov                 byte ptr [edi + 1], al
            //   7e20                 | jle                 0x22
            //   8bc6                 | mov                 eax, esi

        $sequence_6 = { 85db 0f84af040000 6a00 6a00 6a00 6a00 }
            // n = 6, score = 100
            //   85db                 | test                ebx, ebx
            //   0f84af040000         | je                  0x4b5
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_7 = { 0bcd 89442418 c1e108 0bce 8948fc 8b4c2414 }
            // n = 6, score = 100
            //   0bcd                 | or                  ecx, ebp
            //   89442418             | mov                 dword ptr [esp + 0x18], eax
            //   c1e108               | shl                 ecx, 8
            //   0bce                 | or                  ecx, esi
            //   8948fc               | mov                 dword ptr [eax - 4], ecx
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]

        $sequence_8 = { 894c2418 8d149518000000 89442414 3bca 0f8260ffffff 5f 5e }
            // n = 7, score = 100
            //   894c2418             | mov                 dword ptr [esp + 0x18], ecx
            //   8d149518000000       | lea                 edx, [edx*4 + 0x18]
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   3bca                 | cmp                 ecx, edx
            //   0f8260ffffff         | jb                  0xffffff66
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_9 = { 8b442410 8b10 8d4c2414 51 53 53 50 }
            // n = 7, score = 100
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   8d4c2414             | lea                 ecx, [esp + 0x14]
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   50                   | push                eax

    condition:
        7 of them and filesize < 139264
}