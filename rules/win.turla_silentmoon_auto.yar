rule win_turla_silentmoon_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.turla_silentmoon."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.turla_silentmoon"
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
        $sequence_0 = { d3e7 83c003 89865c020000 09be58020000 3bc2 7c2e }
            // n = 6, score = 300
            //   d3e7                 | shl                 edi, cl
            //   83c003               | add                 eax, 3
            //   89865c020000         | mov                 dword ptr [esi + 0x25c], eax
            //   09be58020000         | or                  dword ptr [esi + 0x258], edi
            //   3bc2                 | cmp                 eax, edx
            //   7c2e                 | jl                  0x30

        $sequence_1 = { 6a08 51 8945fc ff15???????? 8bf0 85f6 }
            // n = 6, score = 300
            //   6a08                 | push                8
            //   51                   | push                ecx
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi

        $sequence_2 = { 85c0 7539 6a08 6a01 68???????? 68???????? 68???????? }
            // n = 7, score = 300
            //   85c0                 | test                eax, eax
            //   7539                 | jne                 0x3b
            //   6a08                 | push                8
            //   6a01                 | push                1
            //   68????????           |                     
            //   68????????           |                     
            //   68????????           |                     

        $sequence_3 = { 83be5c02000008 8b55e8 7dd1 8b45dc b91f000000 2b8e5c020000 33ff }
            // n = 7, score = 300
            //   83be5c02000008       | cmp                 dword ptr [esi + 0x25c], 8
            //   8b55e8               | mov                 edx, dword ptr [ebp - 0x18]
            //   7dd1                 | jge                 0xffffffd3
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   b91f000000           | mov                 ecx, 0x1f
            //   2b8e5c020000         | sub                 ecx, dword ptr [esi + 0x25c]
            //   33ff                 | xor                 edi, edi

        $sequence_4 = { 75c6 8a543805 8a5c3e05 3ada 75ba }
            // n = 5, score = 300
            //   75c6                 | jne                 0xffffffc8
            //   8a543805             | mov                 dl, byte ptr [eax + edi + 5]
            //   8a5c3e05             | mov                 bl, byte ptr [esi + edi + 5]
            //   3ada                 | cmp                 bl, dl
            //   75ba                 | jne                 0xffffffbc

        $sequence_5 = { 8b7df8 8bbcbdd0f3ffff 8bc2 d1f8 8bb485e0fbffff 8bca 3bbcb5d0f3ffff }
            // n = 7, score = 300
            //   8b7df8               | mov                 edi, dword ptr [ebp - 8]
            //   8bbcbdd0f3ffff       | mov                 edi, dword ptr [ebp + edi*4 - 0xc30]
            //   8bc2                 | mov                 eax, edx
            //   d1f8                 | sar                 eax, 1
            //   8bb485e0fbffff       | mov                 esi, dword ptr [ebp + eax*4 - 0x420]
            //   8bca                 | mov                 ecx, edx
            //   3bbcb5d0f3ffff       | cmp                 edi, dword ptr [ebp + esi*4 - 0xc30]

        $sequence_6 = { 7416 8d4df0 51 8d45e0 8d75f4 e8???????? 83c404 }
            // n = 7, score = 300
            //   7416                 | je                  0x18
            //   8d4df0               | lea                 ecx, dword ptr [ebp - 0x10]
            //   51                   | push                ecx
            //   8d45e0               | lea                 eax, dword ptr [ebp - 0x20]
            //   8d75f4               | lea                 esi, dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_7 = { 3d20030000 7e09 5f 5e 32c0 5b 8be5 }
            // n = 7, score = 300
            //   3d20030000           | cmp                 eax, 0x320
            //   7e09                 | jle                 0xb
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   32c0                 | xor                 al, al
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp

        $sequence_8 = { be01000000 32db 3bce 0f8cbd000000 8dbdc4ebffff 33d2 }
            // n = 6, score = 300
            //   be01000000           | mov                 esi, 1
            //   32db                 | xor                 bl, bl
            //   3bce                 | cmp                 ecx, esi
            //   0f8cbd000000         | jl                  0xc3
            //   8dbdc4ebffff         | lea                 edi, dword ptr [ebp - 0x143c]
            //   33d2                 | xor                 edx, edx

        $sequence_9 = { 7e68 837d1804 7c26 8bc7 }
            // n = 4, score = 300
            //   7e68                 | jle                 0x6a
            //   837d1804             | cmp                 dword ptr [ebp + 0x18], 4
            //   7c26                 | jl                  0x28
            //   8bc7                 | mov                 eax, edi

    condition:
        7 of them and filesize < 204800
}