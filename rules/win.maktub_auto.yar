rule win_maktub_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.maktub."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.maktub"
        malpedia_rule_date = "20211007"
        malpedia_hash = "e5b790e0f888f252d49063a1251ca60ec2832535"
        malpedia_version = "20211008"
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
        $sequence_0 = { ffd0 f7d8 1bc0 f7d8 8be5 }
            // n = 5, score = 400
            //   ffd0                 | call                eax
            //   f7d8                 | neg                 eax
            //   1bc0                 | sbb                 eax, eax
            //   f7d8                 | neg                 eax
            //   8be5                 | mov                 esp, ebp

        $sequence_1 = { c3 8b4604 48 83f803 }
            // n = 4, score = 300
            //   c3                   | ret                 
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   48                   | dec                 eax
            //   83f803               | cmp                 eax, 3

        $sequence_2 = { ff15???????? a3???????? 56 8b35???????? 6a00 50 }
            // n = 6, score = 300
            //   ff15????????         |                     
            //   a3????????           |                     
            //   56                   | push                esi
            //   8b35????????         |                     
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_3 = { ff15???????? a3???????? 56 6a00 50 ffd3 85ff }
            // n = 7, score = 300
            //   ff15????????         |                     
            //   a3????????           |                     
            //   56                   | push                esi
            //   6a00                 | push                0
            //   50                   | push                eax
            //   ffd3                 | call                ebx
            //   85ff                 | test                edi, edi

        $sequence_4 = { ff4df8 881407 8b03 8948f4 }
            // n = 4, score = 300
            //   ff4df8               | dec                 dword ptr [ebp - 8]
            //   881407               | mov                 byte ptr [edi + eax], dl
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   8948f4               | mov                 dword ptr [eax - 0xc], ecx

        $sequence_5 = { ff15???????? a3???????? 56 6a08 50 ff15???????? }
            // n = 6, score = 300
            //   ff15????????         |                     
            //   a3????????           |                     
            //   56                   | push                esi
            //   6a08                 | push                8
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_6 = { c3 8b4144 8b5124 5e 881c02 }
            // n = 5, score = 300
            //   c3                   | ret                 
            //   8b4144               | mov                 eax, dword ptr [ecx + 0x44]
            //   8b5124               | mov                 edx, dword ptr [ecx + 0x24]
            //   5e                   | pop                 esi
            //   881c02               | mov                 byte ptr [edx + eax], bl

        $sequence_7 = { ff7004 ff30 e8???????? 8bc7 5f 5e }
            // n = 6, score = 200
            //   ff7004               | push                dword ptr [eax + 4]
            //   ff30                 | push                dword ptr [eax]
            //   e8????????           |                     
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_8 = { c1f803 89442418 3bc6 761d 68aa000000 }
            // n = 5, score = 100
            //   c1f803               | sar                 eax, 3
            //   89442418             | mov                 dword ptr [esp + 0x18], eax
            //   3bc6                 | cmp                 eax, esi
            //   761d                 | jbe                 0x1f
            //   68aa000000           | push                0xaa

        $sequence_9 = { c1f803 3bf8 0f42f8 68c7000000 8d470a 68???????? 50 }
            // n = 7, score = 100
            //   c1f803               | sar                 eax, 3
            //   3bf8                 | cmp                 edi, eax
            //   0f42f8               | cmovb               edi, eax
            //   68c7000000           | push                0xc7
            //   8d470a               | lea                 eax, dword ptr [edi + 0xa]
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_10 = { 8d4dfc 8a18 e8???????? 8bc8 }
            // n = 4, score = 100
            //   8d4dfc               | lea                 ecx, dword ptr [ebp - 4]
            //   8a18                 | mov                 bl, byte ptr [eax]
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax

        $sequence_11 = { c1f803 8be8 85c0 7437 }
            // n = 4, score = 100
            //   c1f803               | sar                 eax, 3
            //   8be8                 | mov                 ebp, eax
            //   85c0                 | test                eax, eax
            //   7437                 | je                  0x39

        $sequence_12 = { c1f806 03348520594f00 f6462d01 7414 }
            // n = 4, score = 100
            //   c1f806               | sar                 eax, 6
            //   03348520594f00       | add                 esi, dword ptr [eax*4 + 0x4f5920]
            //   f6462d01             | test                byte ptr [esi + 0x2d], 1
            //   7414                 | je                  0x16

        $sequence_13 = { 8d4dfc 2bc2 d1f8 8bd0 }
            // n = 4, score = 100
            //   8d4dfc               | lea                 ecx, dword ptr [ebp - 4]
            //   2bc2                 | sub                 eax, edx
            //   d1f8                 | sar                 eax, 1
            //   8bd0                 | mov                 edx, eax

        $sequence_14 = { 8d4dfc 56 57 8d7b44 }
            // n = 4, score = 100
            //   8d4dfc               | lea                 ecx, dword ptr [ebp - 4]
            //   56                   | push                esi
            //   57                   | push                edi
            //   8d7b44               | lea                 edi, dword ptr [ebx + 0x44]

        $sequence_15 = { c1f804 83e20f 83e00f 0fb6809c8a4c00 }
            // n = 4, score = 100
            //   c1f804               | sar                 eax, 4
            //   83e20f               | and                 edx, 0xf
            //   83e00f               | and                 eax, 0xf
            //   0fb6809c8a4c00       | movzx               eax, byte ptr [eax + 0x4c8a9c]

        $sequence_16 = { c1f806 6bc930 57 8b048520594f00 }
            // n = 4, score = 100
            //   c1f806               | sar                 eax, 6
            //   6bc930               | imul                ecx, ecx, 0x30
            //   57                   | push                edi
            //   8b048520594f00       | mov                 eax, dword ptr [eax*4 + 0x4f5920]

        $sequence_17 = { 8d4df8 ff7508 e8???????? 50 }
            // n = 4, score = 100
            //   8d4df8               | lea                 ecx, dword ptr [ebp - 8]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   50                   | push                eax

        $sequence_18 = { 8d4dfc 56 e8???????? 8b4508 }
            // n = 4, score = 100
            //   8d4dfc               | lea                 ecx, dword ptr [ebp - 4]
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_19 = { 8d4dfc 8b00 8906 e8???????? }
            // n = 4, score = 100
            //   8d4dfc               | lea                 ecx, dword ptr [ebp - 4]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8906                 | mov                 dword ptr [esi], eax
            //   e8????????           |                     

        $sequence_20 = { 8d4dfc 84c0 75d3 e8???????? }
            // n = 4, score = 100
            //   8d4dfc               | lea                 ecx, dword ptr [ebp - 4]
            //   84c0                 | test                al, al
            //   75d3                 | jne                 0xffffffd5
            //   e8????????           |                     

    condition:
        7 of them and filesize < 3063808
}