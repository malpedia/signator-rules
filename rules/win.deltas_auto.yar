rule win_deltas_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.deltas."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.deltas"
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
        $sequence_0 = { ff15???????? 8be8 8b4320 8b542474 6a40 894500 }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   8be8                 | mov                 ebp, eax
            //   8b4320               | mov                 eax, dword ptr [ebx + 0x20]
            //   8b542474             | mov                 edx, dword ptr [esp + 0x74]
            //   6a40                 | push                0x40
            //   894500               | mov                 dword ptr [ebp], eax

        $sequence_1 = { 8b442424 85c0 7433 3bc5 722f 56 }
            // n = 6, score = 200
            //   8b442424             | mov                 eax, dword ptr [esp + 0x24]
            //   85c0                 | test                eax, eax
            //   7433                 | je                  0x35
            //   3bc5                 | cmp                 eax, ebp
            //   722f                 | jb                  0x31
            //   56                   | push                esi

        $sequence_2 = { 5d b803000000 5b 81c444040000 c3 8d740458 b910000000 }
            // n = 7, score = 200
            //   5d                   | pop                 ebp
            //   b803000000           | mov                 eax, 3
            //   5b                   | pop                 ebx
            //   81c444040000         | add                 esp, 0x444
            //   c3                   | ret                 
            //   8d740458             | lea                 esi, [esp + eax + 0x58]
            //   b910000000           | mov                 ecx, 0x10

        $sequence_3 = { 0f849c050000 399c24d0000000 0f848f050000 3bc3 0f8487050000 }
            // n = 5, score = 200
            //   0f849c050000         | je                  0x5a2
            //   399c24d0000000       | cmp                 dword ptr [esp + 0xd0], ebx
            //   0f848f050000         | je                  0x595
            //   3bc3                 | cmp                 eax, ebx
            //   0f8487050000         | je                  0x58d

        $sequence_4 = { 83e103 33c0 f3a4 5f 896b08 5e 5d }
            // n = 7, score = 200
            //   83e103               | and                 ecx, 3
            //   33c0                 | xor                 eax, eax
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   5f                   | pop                 edi
            //   896b08               | mov                 dword ptr [ebx + 8], ebp
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp

        $sequence_5 = { 8d7c2454 bd10000000 8d7102 33c9 33db 8a4e01 8a1e }
            // n = 7, score = 200
            //   8d7c2454             | lea                 edi, [esp + 0x54]
            //   bd10000000           | mov                 ebp, 0x10
            //   8d7102               | lea                 esi, [ecx + 2]
            //   33c9                 | xor                 ecx, ecx
            //   33db                 | xor                 ebx, ebx
            //   8a4e01               | mov                 cl, byte ptr [esi + 1]
            //   8a1e                 | mov                 bl, byte ptr [esi]

        $sequence_6 = { 898d48020000 89bd88440000 8d8588040000 b900100000 3938 }
            // n = 5, score = 200
            //   898d48020000         | mov                 dword ptr [ebp + 0x248], ecx
            //   89bd88440000         | mov                 dword ptr [ebp + 0x4488], edi
            //   8d8588040000         | lea                 eax, [ebp + 0x488]
            //   b900100000           | mov                 ecx, 0x1000
            //   3938                 | cmp                 dword ptr [eax], edi

        $sequence_7 = { 740b 8d54241c 52 ff15???????? 68???????? ff15???????? 8d842420010000 }
            // n = 7, score = 200
            //   740b                 | je                  0xd
            //   8d54241c             | lea                 edx, [esp + 0x1c]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   68????????           |                     
            //   ff15????????         |                     
            //   8d842420010000       | lea                 eax, [esp + 0x120]

        $sequence_8 = { 88442405 88442408 b06c 57 8b3d???????? 8844240d 88442412 }
            // n = 7, score = 200
            //   88442405             | mov                 byte ptr [esp + 5], al
            //   88442408             | mov                 byte ptr [esp + 8], al
            //   b06c                 | mov                 al, 0x6c
            //   57                   | push                edi
            //   8b3d????????         |                     
            //   8844240d             | mov                 byte ptr [esp + 0xd], al
            //   88442412             | mov                 byte ptr [esp + 0x12], al

        $sequence_9 = { 8b35???????? 8d442470 50 885c2467 ffd6 8d8c2480000000 8bf8 }
            // n = 7, score = 200
            //   8b35????????         |                     
            //   8d442470             | lea                 eax, [esp + 0x70]
            //   50                   | push                eax
            //   885c2467             | mov                 byte ptr [esp + 0x67], bl
            //   ffd6                 | call                esi
            //   8d8c2480000000       | lea                 ecx, [esp + 0x80]
            //   8bf8                 | mov                 edi, eax

    condition:
        7 of them and filesize < 90112
}