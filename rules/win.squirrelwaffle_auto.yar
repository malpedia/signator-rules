rule win_squirrelwaffle_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.squirrelwaffle."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.squirrelwaffle"
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
        $sequence_0 = { 46 3bf7 7cdd 8bb564f7ffff }
            // n = 4, score = 700
            //   46                   | inc                 esi
            //   3bf7                 | cmp                 esi, edi
            //   7cdd                 | jl                  0xffffffdf
            //   8bb564f7ffff         | mov                 esi, dword ptr [ebp - 0x89c]

        $sequence_1 = { 8bce 894640 a1???????? 894644 8d45dc }
            // n = 5, score = 700
            //   8bce                 | mov                 ecx, esi
            //   894640               | mov                 dword ptr [esi + 0x40], eax
            //   a1????????           |                     
            //   894644               | mov                 dword ptr [esi + 0x44], eax
            //   8d45dc               | lea                 eax, [ebp - 0x24]

        $sequence_2 = { ffb564f7ffff ff15???????? 8b761c c78564f7ffffffffffff }
            // n = 4, score = 700
            //   ffb564f7ffff         | push                dword ptr [ebp - 0x89c]
            //   ff15????????         |                     
            //   8b761c               | mov                 esi, dword ptr [esi + 0x1c]
            //   c78564f7ffffffffffff     | mov    dword ptr [ebp - 0x89c], 0xffffffff

        $sequence_3 = { 8d040a 03c7 50 8b4508 03c2 50 }
            // n = 6, score = 700
            //   8d040a               | lea                 eax, [edx + ecx]
            //   03c7                 | add                 eax, edi
            //   50                   | push                eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   03c2                 | add                 eax, edx
            //   50                   | push                eax

        $sequence_4 = { 83fa10 722f 8b8d10f7ffff 42 }
            // n = 4, score = 700
            //   83fa10               | cmp                 edx, 0x10
            //   722f                 | jb                  0x31
            //   8b8d10f7ffff         | mov                 ecx, dword ptr [ebp - 0x8f0]
            //   42                   | inc                 edx

        $sequence_5 = { 8b45e8 8d55d8 0f43d7 8d4dd8 0f43cf 03c2 50 }
            // n = 7, score = 700
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   8d55d8               | lea                 edx, [ebp - 0x28]
            //   0f43d7               | cmovae              edx, edi
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   0f43cf               | cmovae              ecx, edi
            //   03c2                 | add                 eax, edx
            //   50                   | push                eax

        $sequence_6 = { c6464801 88463d ff15???????? 85ff 7446 8d45f0 }
            // n = 6, score = 700
            //   c6464801             | mov                 byte ptr [esi + 0x48], 1
            //   88463d               | mov                 byte ptr [esi + 0x3d], al
            //   ff15????????         |                     
            //   85ff                 | test                edi, edi
            //   7446                 | je                  0x48
            //   8d45f0               | lea                 eax, [ebp - 0x10]

        $sequence_7 = { 6888020000 c745fc00000000 6a00 c7459088020000 ff15???????? }
            // n = 5, score = 700
            //   6888020000           | push                0x288
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   6a00                 | push                0
            //   c7459088020000       | mov                 dword ptr [ebp - 0x70], 0x288
            //   ff15????????         |                     

        $sequence_8 = { 83f8ff 751d ffb564f7ffff ff15???????? 8b761c c78564f7ffffffffffff }
            // n = 6, score = 700
            //   83f8ff               | cmp                 eax, -1
            //   751d                 | jne                 0x1f
            //   ffb564f7ffff         | push                dword ptr [ebp - 0x89c]
            //   ff15????????         |                     
            //   8b761c               | mov                 esi, dword ptr [esi + 0x1c]
            //   c78564f7ffffffffffff     | mov    dword ptr [ebp - 0x89c], 0xffffffff

        $sequence_9 = { 43 3bde 7ca5 8b75ec 83fe03 7d44 }
            // n = 6, score = 700
            //   43                   | inc                 ebx
            //   3bde                 | cmp                 ebx, esi
            //   7ca5                 | jl                  0xffffffa7
            //   8b75ec               | mov                 esi, dword ptr [ebp - 0x14]
            //   83fe03               | cmp                 esi, 3
            //   7d44                 | jge                 0x46

    condition:
        7 of them and filesize < 147456
}