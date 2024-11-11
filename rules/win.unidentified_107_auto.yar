rule win_unidentified_107_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.unidentified_107."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_107"
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
        $sequence_0 = { 4c09f2 4585c0 490f49d0 4829c2 4c8d3c0a 4889f1 }
            // n = 6, score = 300
            //   4c09f2               | mov                 eax, dword ptr [ebp - 0x10]
            //   4585c0               | dec                 eax
            //   490f49d0             | add                 edx, eax
            //   4829c2               | dec                 eax
            //   4c8d3c0a             | mov                 eax, dword ptr [ebp - 0x90]
            //   4889f1               | dec                 eax

        $sequence_1 = { 75dc 4c89e9 4883c420 5b 5e 5f 415c }
            // n = 7, score = 300
            //   75dc                 | dec                 eax
            //   4c89e9               | mov                 dword ptr [esp + 0x20], edx
            //   4883c420             | dec                 ecx
            //   5b                   | mov                 ecx, ebx
            //   5e                   | dec                 eax
            //   5f                   | mov                 edx, eax
            //   415c                 | dec                 eax

        $sequence_2 = { 85d2 0f8ea1feffff 488b35???????? 31db }
            // n = 4, score = 300
            //   85d2                 | dec                 esp
            //   0f8ea1feffff         | mov                 ecx, esp
            //   488b35????????       |                     
            //   31db                 | dec                 esp

        $sequence_3 = { 7e96 8b13 4883f80b 0f8f33010000 }
            // n = 4, score = 300
            //   7e96                 | stc                 
            //   8b13                 | jecxz               0x4c
            //   4883f80b             | dec                 ecx
            //   0f8f33010000         | mov                 esi, eax

        $sequence_4 = { 4883ec28 8b05???????? 89cf 4889d6 }
            // n = 4, score = 300
            //   4883ec28             | dec                 eax
            //   8b05????????         |                     
            //   89cf                 | add                 edx, ecx
            //   4889d6               | mov                 byte ptr [edx], al

        $sequence_5 = { 4c89442418 4c894c2420 4883ec64 48c7c12f398d13 e8???????? }
            // n = 5, score = 300
            //   4c89442418           | dec                 eax
            //   4c894c2420           | mov                 edi, edx
            //   4883ec64             | dec                 eax
            //   48c7c12f398d13       | test                ecx, ecx
            //   e8????????           |                     

        $sequence_6 = { 8916 4189d4 4c89c3 85d2 755c 8b05???????? 85c0 }
            // n = 7, score = 300
            //   8916                 | dec                 ecx
            //   4189d4               | mov                 ebp, edx
            //   4c89c3               | dec                 esp
            //   85d2                 | mov                 ebx, ecx
            //   755c                 | dec                 ebp
            //   8b05????????         |                     
            //   85c0                 | mov                 esp, eax

        $sequence_7 = { e8???????? 4189c6 85c0 0f84f2000000 4183fc01 0f856e010000 e8???????? }
            // n = 7, score = 300
            //   e8????????           |                     
            //   4189c6               | ret                 
            //   85c0                 | mov                 edx, dword ptr [ebp - 4]
            //   0f84f2000000         | dec                 eax
            //   4183fc01             | mov                 eax, dword ptr [ebp + 0x40]
            //   0f856e010000         | dec                 eax
            //   e8????????           |                     

        $sequence_8 = { 0f84e6000000 488b05???????? 488d1c9b 48c1e303 4801d8 }
            // n = 5, score = 300
            //   0f84e6000000         | cmp                 eax, 1
            //   488b05????????       |                     
            //   488d1c9b             | jbe                 0x26
            //   48c1e303             | mov                 dword ptr [ebp + 0x18], eax
            //   4801d8               | movzx               eax, byte ptr [ebp - 1]

        $sequence_9 = { 8938 48897008 4c89e1 ff15???????? 488b05???????? }
            // n = 5, score = 300
            //   8938                 | mov                 eax, esp
            //   48897008             | dec                 eax
            //   4c89e1               | sub                 eax, ebx
            //   ff15????????         |                     
            //   488b05????????       |                     

    condition:
        7 of them and filesize < 254976
}