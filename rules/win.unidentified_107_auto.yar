rule win_unidentified_107_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.unidentified_107."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_107"
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
        $sequence_0 = { 4139d9 75d8 4c89e1 e8???????? }
            // n = 4, score = 300
            //   4139d9               | xor                 eax, eax
            //   75d8                 | inc                 ecx
            //   4c89e1               | mov                 byte ptr [ecx + eax], al
            //   e8????????           |                     

        $sequence_1 = { 48897008 4c89e1 ff15???????? 488b05???????? 4c89e1 48891d???????? }
            // n = 6, score = 300
            //   48897008             | jbe                 0x468
            //   4c89e1               | nop                 
            //   ff15????????         |                     
            //   488b05????????       |                     
            //   4c89e1               | dec                 eax
            //   48891d????????       |                     

        $sequence_2 = { 0f83d6fdffff 4c8b35???????? 8b7304 448b2b 4883c308 4c01f6 44032e }
            // n = 7, score = 300
            //   0f83d6fdffff         | mov                 ebp, esp
            //   4c8b35????????       |                     
            //   8b7304               | dec                 eax
            //   448b2b               | sub                 esp, 0x20
            //   4883c308             | mov                 ecx, 0x6a4abc5b
            //   4c01f6               | ret                 
            //   44032e               | push                ebp

        $sequence_3 = { 034208 4839c1 7214 4883c228 }
            // n = 4, score = 300
            //   034208               | add                 eax, edx
            //   4839c1               | inc                 esp
            //   7214                 | add                 eax, edx
            //   4883c228             | inc                 esp

        $sequence_4 = { 0f8584000000 4c8b3e 4929c7 4901cf }
            // n = 4, score = 300
            //   0f8584000000         | add                 eax, 1
            //   4c8b3e               | je                  0xd0
            //   4929c7               | dec                 ecx
            //   4901cf               | mov                 ecx, esi

        $sequence_5 = { e8???????? 4c89e1 ff15???????? 31c0 4883c428 }
            // n = 5, score = 300
            //   e8????????           |                     
            //   4c89e1               | jne                 0x1e4
            //   ff15????????         |                     
            //   31c0                 | jmp                 0x28c
            //   4883c428             | test                eax, eax

        $sequence_6 = { 8b15???????? 85d2 0f8ea1feffff 488b35???????? 31db 4c8d65fc }
            // n = 6, score = 300
            //   8b15????????         |                     
            //   85d2                 | dec                 eax
            //   0f8ea1feffff         | mov                 ecx, eax
            //   488b35????????       |                     
            //   31db                 | jne                 0x3cd
            //   4c8d65fc             | dec                 eax

        $sequence_7 = { e8???????? 4989c7 48b9ca0e99c700000000 e8???????? 4883c464 488b4c2408 }
            // n = 6, score = 300
            //   e8????????           |                     
            //   4989c7               | jmp                 0x57f
            //   48b9ca0e99c700000000     | mov    eax, dword ptr [ebp - 4]
            //   e8????????           |                     
            //   4883c464             | dec                 eax
            //   488b4c2408           | shl                 eax, 4

        $sequence_8 = { 4183fc01 0f85a9feffff 8b05???????? 85c0 0f8e9bfeffff 83e801 488b1d???????? }
            // n = 7, score = 300
            //   4183fc01             | dec                 eax
            //   0f85a9feffff         | mov                 edx, eax
            //   8b05????????         |                     
            //   85c0                 | dec                 eax
            //   0f8e9bfeffff         | mov                 eax, dword ptr [ebp + 0x78]
            //   83e801               | dec                 eax
            //   488b1d????????       |                     

        $sequence_9 = { 4c89442418 4c894c2420 4883ec64 48c7c10f15af3d }
            // n = 4, score = 300
            //   4c89442418           | lea                 edx, [0xfffffefa]
            //   4c894c2420           | dec                 esp
            //   4883ec64             | mov                 ecx, dword ptr [esp + 0x28]
            //   48c7c10f15af3d       | dec                 esp

    condition:
        7 of them and filesize < 254976
}