rule win_glooxmail_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.glooxmail."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.glooxmail"
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
        $sequence_0 = { c68424640800004e 8b07 51 8bcf ff5010 53 6a01 }
            // n = 7, score = 100
            //   c68424640800004e     | mov                 byte ptr [esp + 0x864], 0x4e
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   51                   | push                ecx
            //   8bcf                 | mov                 ecx, edi
            //   ff5010               | call                dword ptr [eax + 0x10]
            //   53                   | push                ebx
            //   6a01                 | push                1

        $sequence_1 = { 8b00 81c74c040000 8944240c 8b07 89442408 837c240800 8b7714 }
            // n = 7, score = 100
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   81c74c040000         | add                 edi, 0x44c
            //   8944240c             | mov                 dword ptr [esp + 0xc], eax
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   837c240800           | cmp                 dword ptr [esp + 8], 0
            //   8b7714               | mov                 esi, dword ptr [edi + 0x14]

        $sequence_2 = { ff7508 ff17 eb46 8b450c 83e800 7416 48 }
            // n = 7, score = 100
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff17                 | call                dword ptr [edi]
            //   eb46                 | jmp                 0x48
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   83e800               | sub                 eax, 0
            //   7416                 | je                  0x18
            //   48                   | dec                 eax

        $sequence_3 = { 85c0 7571 ff35???????? ff15???????? 68e8030000 ff15???????? e8???????? }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   7571                 | jne                 0x73
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   68e8030000           | push                0x3e8
            //   ff15????????         |                     
            //   e8????????           |                     

        $sequence_4 = { 8db510ffffff e9???????? 8d8dbcfeffff e9???????? 8b850cffffff 83e008 0f8412000000 }
            // n = 7, score = 100
            //   8db510ffffff         | lea                 esi, [ebp - 0xf0]
            //   e9????????           |                     
            //   8d8dbcfeffff         | lea                 ecx, [ebp - 0x144]
            //   e9????????           |                     
            //   8b850cffffff         | mov                 eax, dword ptr [ebp - 0xf4]
            //   83e008               | and                 eax, 8
            //   0f8412000000         | je                  0x18

        $sequence_5 = { f6c301 7412 6a00 6a01 8d8d24ffffff 83e3fe e8???????? }
            // n = 7, score = 100
            //   f6c301               | test                bl, 1
            //   7412                 | je                  0x14
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   8d8d24ffffff         | lea                 ecx, [ebp - 0xdc]
            //   83e3fe               | and                 ebx, 0xfffffffe
            //   e8????????           |                     

        $sequence_6 = { 40 6a01 50 e8???????? 59 59 894638 }
            // n = 7, score = 100
            //   40                   | inc                 eax
            //   6a01                 | push                1
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   894638               | mov                 dword ptr [esi + 0x38], eax

        $sequence_7 = { 8d420c 8b4a9c 33c8 e8???????? b8???????? e9???????? 8d4db4 }
            // n = 7, score = 100
            //   8d420c               | lea                 eax, [edx + 0xc]
            //   8b4a9c               | mov                 ecx, dword ptr [edx - 0x64]
            //   33c8                 | xor                 ecx, eax
            //   e8????????           |                     
            //   b8????????           |                     
            //   e9????????           |                     
            //   8d4db4               | lea                 ecx, [ebp - 0x4c]

        $sequence_8 = { 50 6800200000 8d9f84030000 6a00 c78424a400000002000000 e8???????? 838c2498000000ff }
            // n = 7, score = 100
            //   50                   | push                eax
            //   6800200000           | push                0x2000
            //   8d9f84030000         | lea                 ebx, [edi + 0x384]
            //   6a00                 | push                0
            //   c78424a400000002000000     | mov    dword ptr [esp + 0xa4], 2
            //   e8????????           |                     
            //   838c2498000000ff     | or                  dword ptr [esp + 0x98], 0xffffffff

        $sequence_9 = { 8d75d0 e8???????? 50 8d45b4 50 c745fc03000000 e8???????? }
            // n = 7, score = 100
            //   8d75d0               | lea                 esi, [ebp - 0x30]
            //   e8????????           |                     
            //   50                   | push                eax
            //   8d45b4               | lea                 eax, [ebp - 0x4c]
            //   50                   | push                eax
            //   c745fc03000000       | mov                 dword ptr [ebp - 4], 3
            //   e8????????           |                     

    condition:
        7 of them and filesize < 761856
}