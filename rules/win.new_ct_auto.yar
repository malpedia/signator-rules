rule win_new_ct_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.new_ct."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.new_ct"
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
        $sequence_0 = { 48 750e 8b442408 a3???????? a3???????? }
            // n = 5, score = 200
            //   48                   | dec                 eax
            //   750e                 | jne                 0x10
            //   8b442408             | mov                 eax, dword ptr [esp + 8]
            //   a3????????           |                     
            //   a3????????           |                     

        $sequence_1 = { 53 c7858003000000000000 ffd6 5f }
            // n = 4, score = 200
            //   53                   | push                ebx
            //   c7858003000000000000     | mov    dword ptr [ebp + 0x380], 0
            //   ffd6                 | call                esi
            //   5f                   | pop                 edi

        $sequence_2 = { b814200000 e8???????? a1???????? 8b0d???????? }
            // n = 4, score = 200
            //   b814200000           | mov                 eax, 0x2014
            //   e8????????           |                     
            //   a1????????           |                     
            //   8b0d????????         |                     

        $sequence_3 = { 49 8d44240c 51 50 56 }
            // n = 5, score = 200
            //   49                   | dec                 ecx
            //   8d44240c             | lea                 eax, [esp + 0xc]
            //   51                   | push                ecx
            //   50                   | push                eax
            //   56                   | push                esi

        $sequence_4 = { e8???????? 56 e8???????? 83c404 8b45e4 50 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   50                   | push                eax

        $sequence_5 = { 51 e8???????? 85c0 7423 8b500c }
            // n = 5, score = 200
            //   51                   | push                ecx
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7423                 | je                  0x25
            //   8b500c               | mov                 edx, dword ptr [eax + 0xc]

        $sequence_6 = { ff15???????? 8b9580030000 8bce 89420c 8b8580030000 8bd1 897010 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   8b9580030000         | mov                 edx, dword ptr [ebp + 0x380]
            //   8bce                 | mov                 ecx, esi
            //   89420c               | mov                 dword ptr [edx + 0xc], eax
            //   8b8580030000         | mov                 eax, dword ptr [ebp + 0x380]
            //   8bd1                 | mov                 edx, ecx
            //   897010               | mov                 dword ptr [eax + 0x10], esi

        $sequence_7 = { 7403 894608 6888030000 e8???????? 83c404 }
            // n = 5, score = 200
            //   7403                 | je                  5
            //   894608               | mov                 dword ptr [esi + 8], eax
            //   6888030000           | push                0x388
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_8 = { 0500010000 33d2 f7f1 8b8580030000 895004 8b8d80030000 c7410838121220 }
            // n = 7, score = 200
            //   0500010000           | add                 eax, 0x100
            //   33d2                 | xor                 edx, edx
            //   f7f1                 | div                 ecx
            //   8b8580030000         | mov                 eax, dword ptr [ebp + 0x380]
            //   895004               | mov                 dword ptr [eax + 4], edx
            //   8b8d80030000         | mov                 ecx, dword ptr [ebp + 0x380]
            //   c7410838121220       | mov                 dword ptr [ecx + 8], 0x20121238

        $sequence_9 = { 8bb5c4fbffff 56 ff15???????? 85c0 }
            // n = 4, score = 200
            //   8bb5c4fbffff         | mov                 esi, dword ptr [ebp - 0x43c]
            //   56                   | push                esi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

    condition:
        7 of them and filesize < 122880
}