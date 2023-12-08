rule win_nightclub_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.nightclub."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nightclub"
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
        $sequence_0 = { ff4808 83c404 3b7514 75b4 5f 5b 8b450c }
            // n = 7, score = 100
            //   ff4808               | dec                 dword ptr [eax + 8]
            //   83c404               | add                 esp, 4
            //   3b7514               | cmp                 esi, dword ptr [ebp + 0x14]
            //   75b4                 | jne                 0xffffffb6
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_1 = { 8d4dd0 c645f300 ff15???????? 8b4d08 8d45c0 50 51 }
            // n = 7, score = 100
            //   8d4dd0               | lea                 ecx, [ebp - 0x30]
            //   c645f300             | mov                 byte ptr [ebp - 0xd], 0
            //   ff15????????         |                     
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8d45c0               | lea                 eax, [ebp - 0x40]
            //   50                   | push                eax
            //   51                   | push                ecx

        $sequence_2 = { 8d75bc e8???????? 8d75e0 e8???????? eb33 8b55bc 8b7d08 }
            // n = 7, score = 100
            //   8d75bc               | lea                 esi, [ebp - 0x44]
            //   e8????????           |                     
            //   8d75e0               | lea                 esi, [ebp - 0x20]
            //   e8????????           |                     
            //   eb33                 | jmp                 0x35
            //   8b55bc               | mov                 edx, dword ptr [ebp - 0x44]
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]

        $sequence_3 = { 8da42400000000 8a4701 47 84c0 75f8 b90b000000 be???????? }
            // n = 7, score = 100
            //   8da42400000000       | lea                 esp, [esp]
            //   8a4701               | mov                 al, byte ptr [edi + 1]
            //   47                   | inc                 edi
            //   84c0                 | test                al, al
            //   75f8                 | jne                 0xfffffffa
            //   b90b000000           | mov                 ecx, 0xb
            //   be????????           |                     

        $sequence_4 = { 83c404 6a00 56 53 8bf8 ff15???????? }
            // n = 6, score = 100
            //   83c404               | add                 esp, 4
            //   6a00                 | push                0
            //   56                   | push                esi
            //   53                   | push                ebx
            //   8bf8                 | mov                 edi, eax
            //   ff15????????         |                     

        $sequence_5 = { 85c0 7505 a1???????? 8bc8 8bff 8a10 40 }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7
            //   a1????????           |                     
            //   8bc8                 | mov                 ecx, eax
            //   8bff                 | mov                 edi, edi
            //   8a10                 | mov                 dl, byte ptr [eax]
            //   40                   | inc                 eax

        $sequence_6 = { 83c408 8bc8 ff15???????? 5f 5e 8be5 5d }
            // n = 7, score = 100
            //   83c408               | add                 esp, 8
            //   8bc8                 | mov                 ecx, eax
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp

        $sequence_7 = { 5b b87fe0077e f7ef c1fa08 8bfa c1ef1f 03fa }
            // n = 7, score = 100
            //   5b                   | pop                 ebx
            //   b87fe0077e           | mov                 eax, 0x7e07e07f
            //   f7ef                 | imul                edi
            //   c1fa08               | sar                 edx, 8
            //   8bfa                 | mov                 edi, edx
            //   c1ef1f               | shr                 edi, 0x1f
            //   03fa                 | add                 edi, edx

        $sequence_8 = { 8b45f0 83c010 83c310 8945f0 3bc6 75dc }
            // n = 6, score = 100
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   83c010               | add                 eax, 0x10
            //   83c310               | add                 ebx, 0x10
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   3bc6                 | cmp                 eax, esi
            //   75dc                 | jne                 0xffffffde

        $sequence_9 = { c645f200 ff15???????? c745e001000000 85db 0f848c010000 8b15???????? 8b450c }
            // n = 7, score = 100
            //   c645f200             | mov                 byte ptr [ebp - 0xe], 0
            //   ff15????????         |                     
            //   c745e001000000       | mov                 dword ptr [ebp - 0x20], 1
            //   85db                 | test                ebx, ebx
            //   0f848c010000         | je                  0x192
            //   8b15????????         |                     
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

    condition:
        7 of them and filesize < 247808
}