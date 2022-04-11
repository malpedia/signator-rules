rule win_ariabody_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.ariabody."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ariabody"
        malpedia_rule_date = "20220405"
        malpedia_hash = "ecd38294bd47d5589be5cd5490dc8bb4804afc2a"
        malpedia_version = ""
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
        $sequence_0 = { 83ec50 53 57 8bd9 e8???????? }
            // n = 5, score = 300
            //   83ec50               | dec                 esp
            //   53                   | lea                 ecx, dword ptr [esp + 0x168]
            //   57                   | dec                 eax
            //   8bd9                 | mov                 dword ptr [eax + 0x20], 0
            //   e8????????           |                     

        $sequence_1 = { 56 8d0c30 ffd1 8bc6 }
            // n = 4, score = 300
            //   56                   | mov                 edx, ebp
            //   8d0c30               | inc                 ecx
            //   ffd1                 | mov                 eax, 4
            //   8bc6                 | mov                 dword ptr [esp + 0x50], 0x5f327377

        $sequence_2 = { 03c7 50 ff5204 8b1e 8bd0 }
            // n = 5, score = 300
            //   03c7                 | je                  6
            //   50                   | push                esi
            //   ff5204               | lea                 ecx, dword ptr [eax + esi]
            //   8b1e                 | call                ecx
            //   8bd0                 | mov                 eax, esi

        $sequence_3 = { 893e eb13 8b16 8bcf e8???????? }
            // n = 5, score = 300
            //   893e                 | inc                 ecx
            //   eb13                 | call                dword ptr [esi + 0xd0]
            //   8b16                 | mov                 dword ptr [eax + 0x20], 8
            //   8bcf                 | dec                 eax
            //   e8????????           |                     

        $sequence_4 = { 2bd1 8a01 84c0 7406 3ac3 7402 }
            // n = 6, score = 300
            //   2bd1                 | mov                 eax, esp
            //   8a01                 | dec                 ecx
            //   84c0                 | add                 ebp, 0x1ec
            //   7406                 | dec                 esp
            //   3ac3                 | mov                 ecx, esp
            //   7402                 | dec                 esp

        $sequence_5 = { 8bf2 56 8d55fc 03f9 e8???????? 59 85c0 }
            // n = 7, score = 300
            //   8bf2                 | mov                 dword ptr [esi], edi
            //   56                   | jmp                 0x19
            //   8d55fc               | mov                 edx, dword ptr [esi]
            //   03f9                 | mov                 dword ptr [ecx], eax
            //   e8????????           |                     
            //   59                   | xor                 eax, eax
            //   85c0                 | inc                 eax

        $sequence_6 = { 8901 33c0 40 5b 5e 5f }
            // n = 6, score = 300
            //   8901                 | push                edi
            //   33c0                 | mov                 ebx, ecx
            //   40                   | mov                 dword ptr [esi], edi
            //   5b                   | jmp                 0x15
            //   5e                   | mov                 edx, dword ptr [esi]
            //   5f                   | mov                 ecx, edi

        $sequence_7 = { 8bcf 0fb6c0 50 ff75fc e8???????? 83c40c 85db }
            // n = 7, score = 300
            //   8bcf                 | pop                 ebx
            //   0fb6c0               | pop                 esi
            //   50                   | pop                 edi
            //   ff75fc               | mov                 al, byte ptr [ecx]
            //   e8????????           |                     
            //   83c40c               | test                al, al
            //   85db                 | je                  0xa

        $sequence_8 = { c7402008000000 e8???????? 4889e0 4981c5ec010000 4c89e1 4c89ea 41b804000000 }
            // n = 7, score = 100
            //   c7402008000000       | lea                 edx, dword ptr [0xf9cd]
            //   e8????????           |                     
            //   4889e0               | dec                 ebp
            //   4981c5ec010000       | mov                 ecx, dword ptr [ebp]
            //   4c89e1               | dec                 ecx
            //   4c89ea               | add                 ebp, 8
            //   41b804000000         | dec                 ebp

        $sequence_9 = { 488d942444010000 4c8d8c2468010000 48c7402000000000 41ff96d0000000 }
            // n = 4, score = 100
            //   488d942444010000     | dec                 eax
            //   4c8d8c2468010000     | add                 esp, 0x28
            //   48c7402000000000     | ret                 
            //   41ff96d0000000       | dec                 esp

        $sequence_10 = { 4883c010 4883c428 c3 4c8d15cdf90000 }
            // n = 4, score = 100
            //   4883c010             | inc                 ecx
            //   4883c428             | cmp                 dword ptr [esp + edx + 0x50], 0
            //   c3                   | xor                 edx, edx
            //   4c8d15cdf90000       | inc                 ecx

        $sequence_11 = { 89442444 488d052cb70000 4a8b14e8 41837c145000 }
            // n = 4, score = 100
            //   89442444             | call                dword ptr [ebp + 0x1e8]
            //   488d052cb70000       | dec                 esp
            //   4a8b14e8             | mov                 ecx, ebp
            //   41837c145000         | mov                 dword ptr [esp + 0x44], eax

        $sequence_12 = { c74424507773325f 488d4c2450 c7410433322e64 c741086c6c0000 }
            // n = 4, score = 100
            //   c74424507773325f     | test                ecx, ecx
            //   488d4c2450           | jne                 0xffffffcb
            //   c7410433322e64       | inc                 ecx
            //   c741086c6c0000       | mov                 ebp, dword ptr [edi]

        $sequence_13 = { 488d9424b0010000 ff95d8010000 48ffc0 4889c1 ff95e8010000 4c89e9 }
            // n = 6, score = 100
            // 
            //   ff95d8010000         | call                dword ptr [ebp + 0x1d8]
            //   48ffc0               | dec                 eax
            //   4889c1               | inc                 eax
            //   ff95e8010000         | dec                 eax
            //   4c89e9               | mov                 ecx, eax

        $sequence_14 = { 4d8b4d00 4983c508 4d85c9 75c6 418b2f 4883c314 4983c714 }
            // n = 7, score = 100
            //   4d8b4d00             | mov                 eax, 0x800
            //   4983c508             | dec                 eax
            //   4d85c9               | lea                 edx, dword ptr [0x9c0f]
            //   75c6                 | dec                 eax
            //   418b2f               | mov                 ecx, eax
            //   4883c314             | dec                 eax
            //   4983c714             | add                 eax, 0x10

        $sequence_15 = { 33d2 41b800080000 ff15???????? 488d150f9c0000 488bc8 }
            // n = 5, score = 100
            //   33d2                 | dec                 eax
            //   41b800080000         | lea                 eax, dword ptr [0xb72c]
            //   ff15????????         |                     
            //   488d150f9c0000       | dec                 edx
            //   488bc8               | mov                 edx, dword ptr [eax + ebp*8]

    condition:
        7 of them and filesize < 253952
}