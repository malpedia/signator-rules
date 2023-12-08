rule win_herpes_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.herpes."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.herpes"
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
        $sequence_0 = { 7303 8d4570 ffb580000000 50 8b45f0 03c7 }
            // n = 6, score = 100
            //   7303                 | jae                 5
            //   8d4570               | lea                 eax, [ebp + 0x70]
            //   ffb580000000         | push                dword ptr [ebp + 0x80]
            //   50                   | push                eax
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   03c7                 | add                 eax, edi

        $sequence_1 = { 8d9424380d0000 52 ffd6 eb30 6a38 8d4c241c 51 }
            // n = 7, score = 100
            //   8d9424380d0000       | lea                 edx, [esp + 0xd38]
            //   52                   | push                edx
            //   ffd6                 | call                esi
            //   eb30                 | jmp                 0x32
            //   6a38                 | push                0x38
            //   8d4c241c             | lea                 ecx, [esp + 0x1c]
            //   51                   | push                ecx

        $sequence_2 = { 68???????? eb05 68???????? 56 ffd7 bb05000000 399d64ffffff }
            // n = 7, score = 100
            //   68????????           |                     
            //   eb05                 | jmp                 7
            //   68????????           |                     
            //   56                   | push                esi
            //   ffd7                 | call                edi
            //   bb05000000           | mov                 ebx, 5
            //   399d64ffffff         | cmp                 dword ptr [ebp - 0x9c], ebx

        $sequence_3 = { 68???????? 89869c010000 ffb604020000 ffd7 68???????? }
            // n = 5, score = 100
            //   68????????           |                     
            //   89869c010000         | mov                 dword ptr [esi + 0x19c], eax
            //   ffb604020000         | push                dword ptr [esi + 0x204]
            //   ffd7                 | call                edi
            //   68????????           |                     

        $sequence_4 = { 64a300000000 b80f000000 33ff 8985e4feffff 89bde0feffff }
            // n = 5, score = 100
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   b80f000000           | mov                 eax, 0xf
            //   33ff                 | xor                 edi, edi
            //   8985e4feffff         | mov                 dword ptr [ebp - 0x11c], eax
            //   89bde0feffff         | mov                 dword ptr [ebp - 0x120], edi

        $sequence_5 = { 57 ff15???????? 5f 8b4dfc 33cd e8???????? }
            // n = 6, score = 100
            //   57                   | push                edi
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   33cd                 | xor                 ecx, ebp
            //   e8????????           |                     

        $sequence_6 = { ff15???????? 85c0 742a 8b959cfdffff 52 e8???????? }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   742a                 | je                  0x2c
            //   8b959cfdffff         | mov                 edx, dword ptr [ebp - 0x264]
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_7 = { 39bdd4fcffff 7302 8bc3 83ec1c 8bf4 }
            // n = 5, score = 100
            //   39bdd4fcffff         | cmp                 dword ptr [ebp - 0x32c], edi
            //   7302                 | jae                 4
            //   8bc3                 | mov                 eax, ebx
            //   83ec1c               | sub                 esp, 0x1c
            //   8bf4                 | mov                 esi, esp

        $sequence_8 = { 52 ffd6 68???????? 8d858ffeffff 50 }
            // n = 5, score = 100
            //   52                   | push                edx
            //   ffd6                 | call                esi
            //   68????????           |                     
            //   8d858ffeffff         | lea                 eax, [ebp - 0x171]
            //   50                   | push                eax

        $sequence_9 = { 52 6a00 89bde0fcffff ff15???????? 85c0 745e 8d85e4fcffff }
            // n = 7, score = 100
            //   52                   | push                edx
            //   6a00                 | push                0
            //   89bde0fcffff         | mov                 dword ptr [ebp - 0x320], edi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   745e                 | je                  0x60
            //   8d85e4fcffff         | lea                 eax, [ebp - 0x31c]

    condition:
        7 of them and filesize < 319488
}