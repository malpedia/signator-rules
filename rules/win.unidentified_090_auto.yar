rule win_unidentified_090_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.unidentified_090."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_090"
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
        $sequence_0 = { 7447 8b8df8efffff b8619e426b 2bcf f7e9 c1fa0a 8bc2 }
            // n = 7, score = 100
            //   7447                 | je                  0x49
            //   8b8df8efffff         | mov                 ecx, dword ptr [ebp - 0x1008]
            //   b8619e426b           | mov                 eax, 0x6b429e61
            //   2bcf                 | sub                 ecx, edi
            //   f7e9                 | imul                ecx
            //   c1fa0a               | sar                 edx, 0xa
            //   8bc2                 | mov                 eax, edx

        $sequence_1 = { 8d4da4 e8???????? c745fc00000000 33c0 c745e800000000 c745ec07000000 668945d8 }
            // n = 7, score = 100
            //   8d4da4               | lea                 ecx, dword ptr [ebp - 0x5c]
            //   e8????????           |                     
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   33c0                 | xor                 eax, eax
            //   c745e800000000       | mov                 dword ptr [ebp - 0x18], 0
            //   c745ec07000000       | mov                 dword ptr [ebp - 0x14], 7
            //   668945d8             | mov                 word ptr [ebp - 0x28], ax

        $sequence_2 = { 0f44d0 8bca d1e9 8bc1 }
            // n = 4, score = 100
            //   0f44d0               | cmove               edx, eax
            //   8bca                 | mov                 ecx, edx
            //   d1e9                 | shr                 ecx, 1
            //   8bc1                 | mov                 eax, ecx

        $sequence_3 = { 8bbd58f7ffff 8b8734010000 48 83f807 773c ff2485446a0010 68???????? }
            // n = 7, score = 100
            //   8bbd58f7ffff         | mov                 edi, dword ptr [ebp - 0x8a8]
            //   8b8734010000         | mov                 eax, dword ptr [edi + 0x134]
            //   48                   | dec                 eax
            //   83f807               | cmp                 eax, 7
            //   773c                 | ja                  0x3e
            //   ff2485446a0010       | jmp                 dword ptr [eax*4 + 0x10006a44]
            //   68????????           |                     

        $sequence_4 = { 8d4f01 8a07 47 84c0 75f9 8b956cffffff }
            // n = 6, score = 100
            //   8d4f01               | lea                 ecx, dword ptr [edi + 1]
            //   8a07                 | mov                 al, byte ptr [edi]
            //   47                   | inc                 edi
            //   84c0                 | test                al, al
            //   75f9                 | jne                 0xfffffffb
            //   8b956cffffff         | mov                 edx, dword ptr [ebp - 0x94]

        $sequence_5 = { 57 8b7d08 e9???????? 8b1f 8d049d48a40210 8b30 8945fc }
            // n = 7, score = 100
            //   57                   | push                edi
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   e9????????           |                     
            //   8b1f                 | mov                 ebx, dword ptr [edi]
            //   8d049d48a40210       | lea                 eax, dword ptr [ebx*4 + 0x1002a448]
            //   8b30                 | mov                 esi, dword ptr [eax]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_6 = { 668b01 83c102 6685c0 75f5 8b5e14 }
            // n = 5, score = 100
            //   668b01               | mov                 ax, word ptr [ecx]
            //   83c102               | add                 ecx, 2
            //   6685c0               | test                ax, ax
            //   75f5                 | jne                 0xfffffff7
            //   8b5e14               | mov                 ebx, dword ptr [esi + 0x14]

        $sequence_7 = { 6a00 50 c78590f7ffff00000000 c78550f7ffff00000000 c78594f7ffff00000000 e8???????? }
            // n = 6, score = 100
            //   6a00                 | push                0
            //   50                   | push                eax
            //   c78590f7ffff00000000     | mov    dword ptr [ebp - 0x870], 0
            //   c78550f7ffff00000000     | mov    dword ptr [ebp - 0x8b0], 0
            //   c78594f7ffff00000000     | mov    dword ptr [ebp - 0x86c], 0
            //   e8????????           |                     

        $sequence_8 = { c21000 68e8080000 e8???????? 8bf0 897514 68e8080000 6a00 }
            // n = 7, score = 100
            //   c21000               | ret                 0x10
            //   68e8080000           | push                0x8e8
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   897514               | mov                 dword ptr [ebp + 0x14], esi
            //   68e8080000           | push                0x8e8
            //   6a00                 | push                0

        $sequence_9 = { 8bf0 ff15???????? ff742414 ff15???????? 83fe01 0f85ea000000 0f57c0 }
            // n = 7, score = 100
            //   8bf0                 | mov                 esi, eax
            //   ff15????????         |                     
            //   ff742414             | push                dword ptr [esp + 0x14]
            //   ff15????????         |                     
            //   83fe01               | cmp                 esi, 1
            //   0f85ea000000         | jne                 0xf0
            //   0f57c0               | xorps               xmm0, xmm0

    condition:
        7 of them and filesize < 750592
}