rule win_snatch_loader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.snatch_loader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.snatch_loader"
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
        $sequence_0 = { 66397102 740b 42 0fb7c2 }
            // n = 4, score = 600
            //   66397102             | cmp                 word ptr [ecx + 2], si
            //   740b                 | je                  0xd
            //   42                   | inc                 edx
            //   0fb7c2               | movzx               eax, dx

        $sequence_1 = { 66894606 a1???????? 85c0 7522 }
            // n = 4, score = 600
            //   66894606             | mov                 word ptr [esi + 6], ax
            //   a1????????           |                     
            //   85c0                 | test                eax, eax
            //   7522                 | jne                 0x24

        $sequence_2 = { 8bc8 e8???????? a3???????? 85c0 7403 }
            // n = 5, score = 600
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   a3????????           |                     
            //   85c0                 | test                eax, eax
            //   7403                 | je                  5

        $sequence_3 = { 85c0 7505 8b75fc eb04 }
            // n = 4, score = 600
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7
            //   8b75fc               | mov                 esi, dword ptr [ebp - 4]
            //   eb04                 | jmp                 6

        $sequence_4 = { 8b45fc eb0d 53 53 53 53 8d4dfc }
            // n = 7, score = 600
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   eb0d                 | jmp                 0xf
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   8d4dfc               | lea                 ecx, dword ptr [ebp - 4]

        $sequence_5 = { 7505 8b4dfc eb0e 8d4dfc 51 8d4df4 }
            // n = 6, score = 600
            //   7505                 | jne                 7
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   eb0e                 | jmp                 0x10
            //   8d4dfc               | lea                 ecx, dword ptr [ebp - 4]
            //   51                   | push                ecx
            //   8d4df4               | lea                 ecx, dword ptr [ebp - 0xc]

        $sequence_6 = { 42 0fb7c2 6639744102 75f5 }
            // n = 4, score = 600
            //   42                   | inc                 edx
            //   0fb7c2               | movzx               eax, dx
            //   6639744102           | cmp                 word ptr [ecx + eax*2 + 2], si
            //   75f5                 | jne                 0xfffffff7

        $sequence_7 = { 55 8bec 51 53 bb00040000 56 8bcb }
            // n = 7, score = 600
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   bb00040000           | mov                 ebx, 0x400
            //   56                   | push                esi
            //   8bcb                 | mov                 ecx, ebx

        $sequence_8 = { 0bc0 7440 3b45fc 773b }
            // n = 4, score = 500
            //   0bc0                 | or                  eax, eax
            //   7440                 | je                  0x42
            //   3b45fc               | cmp                 eax, dword ptr [ebp - 4]
            //   773b                 | ja                  0x3d

        $sequence_9 = { 5b 5e eb03 83c704 83c304 41 }
            // n = 6, score = 500
            //   5b                   | pop                 ebx
            //   5e                   | pop                 esi
            //   eb03                 | jmp                 5
            //   83c704               | add                 edi, 4
            //   83c304               | add                 ebx, 4
            //   41                   | inc                 ecx

        $sequence_10 = { 57 51 52 ff750c e8???????? 8945fc }
            // n = 6, score = 500
            //   57                   | push                edi
            //   51                   | push                ecx
            //   52                   | push                edx
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_11 = { 33c9 8a0431 0ac0 741f 3a0439 }
            // n = 5, score = 500
            //   33c9                 | xor                 ecx, ecx
            //   8a0431               | mov                 al, byte ptr [ecx + esi]
            //   0ac0                 | or                  al, al
            //   741f                 | je                  0x21
            //   3a0439               | cmp                 al, byte ptr [ecx + edi]

        $sequence_12 = { 8bc2 034508 5a 59 5f }
            // n = 5, score = 500
            //   8bc2                 | mov                 eax, edx
            //   034508               | add                 eax, dword ptr [ebp + 8]
            //   5a                   | pop                 edx
            //   59                   | pop                 ecx
            //   5f                   | pop                 edi

        $sequence_13 = { 56 8b36 56 8b33 33c0 }
            // n = 5, score = 500
            //   56                   | push                esi
            //   8b36                 | mov                 esi, dword ptr [esi]
            //   56                   | push                esi
            //   8b33                 | mov                 esi, dword ptr [ebx]
            //   33c0                 | xor                 eax, eax

        $sequence_14 = { 46 3bf3 76d8 33c0 48 5a }
            // n = 6, score = 500
            //   46                   | inc                 esi
            //   3bf3                 | cmp                 esi, ebx
            //   76d8                 | jbe                 0xffffffda
            //   33c0                 | xor                 eax, eax
            //   48                   | dec                 eax
            //   5a                   | pop                 edx

        $sequence_15 = { 734f ff7510 e8???????? 8945f8 0bc0 }
            // n = 5, score = 500
            //   734f                 | jae                 0x51
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   e8????????           |                     
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   0bc0                 | or                  eax, eax

    condition:
        7 of them and filesize < 262144
}