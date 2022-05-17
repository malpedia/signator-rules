rule win_unidentified_045_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.unidentified_045."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_045"
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
        $sequence_0 = { 381e 75bf 6aff 33f6 46 }
            // n = 5, score = 100
            //   381e                 | cmp                 byte ptr [esi], bl
            //   75bf                 | jne                 0xffffffc1
            //   6aff                 | push                -1
            //   33f6                 | xor                 esi, esi
            //   46                   | inc                 esi

        $sequence_1 = { 7512 8bc3 33c9 893d???????? e8???????? 8945fc }
            // n = 6, score = 100
            //   7512                 | jne                 0x14
            //   8bc3                 | mov                 eax, ebx
            //   33c9                 | xor                 ecx, ecx
            //   893d????????         |                     
            //   e8????????           |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_2 = { 8b4814 034810 3bf9 0f87a5030000 }
            // n = 4, score = 100
            //   8b4814               | mov                 ecx, dword ptr [eax + 0x14]
            //   034810               | add                 ecx, dword ptr [eax + 0x10]
            //   3bf9                 | cmp                 edi, ecx
            //   0f87a5030000         | ja                  0x3ab

        $sequence_3 = { 8945f0 8d45fc 50 ff7510 8d45f0 }
            // n = 5, score = 100
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   8d45f0               | lea                 eax, [ebp - 0x10]

        $sequence_4 = { 8b3d???????? ffd7 895dd8 8b45ac 2b4590 }
            // n = 5, score = 100
            //   8b3d????????         |                     
            //   ffd7                 | call                edi
            //   895dd8               | mov                 dword ptr [ebp - 0x28], ebx
            //   8b45ac               | mov                 eax, dword ptr [ebp - 0x54]
            //   2b4590               | sub                 eax, dword ptr [ebp - 0x70]

        $sequence_5 = { 57 7512 6a08 5f }
            // n = 4, score = 100
            //   57                   | push                edi
            //   7512                 | jne                 0x14
            //   6a08                 | push                8
            //   5f                   | pop                 edi

        $sequence_6 = { 8b45f8 6a02 57 8945e8 8b45e0 }
            // n = 5, score = 100
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   6a02                 | push                2
            //   57                   | push                edi
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]

        $sequence_7 = { 83fe04 751a 8a4106 6a05 5a 32040a }
            // n = 6, score = 100
            //   83fe04               | cmp                 esi, 4
            //   751a                 | jne                 0x1c
            //   8a4106               | mov                 al, byte ptr [ecx + 6]
            //   6a05                 | push                5
            //   5a                   | pop                 edx
            //   32040a               | xor                 al, byte ptr [edx + ecx]

    condition:
        7 of them and filesize < 73728
}