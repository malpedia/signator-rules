rule win_aytoke_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.aytoke."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.aytoke"
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
        $sequence_0 = { 33c0 90 0fb7884c3a4100 66898c05fcfdffff 83c002 6685c9 75e9 }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   90                   | nop                 
            //   0fb7884c3a4100       | movzx               ecx, word ptr [eax + 0x413a4c]
            //   66898c05fcfdffff     | mov                 word ptr [ebp + eax - 0x204], cx
            //   83c002               | add                 eax, 2
            //   6685c9               | test                cx, cx
            //   75e9                 | jne                 0xffffffeb

        $sequence_1 = { ff15???????? 68e8030000 8d9550eeffff 52 53 ff15???????? }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   68e8030000           | push                0x3e8
            //   8d9550eeffff         | lea                 edx, dword ptr [ebp - 0x11b0]
            //   52                   | push                edx
            //   53                   | push                ebx
            //   ff15????????         |                     

        $sequence_2 = { 0fbe84c1183c4100 6a07 c1f804 59 }
            // n = 4, score = 200
            //   0fbe84c1183c4100     | movsx               eax, byte ptr [ecx + eax*8 + 0x413c18]
            //   6a07                 | push                7
            //   c1f804               | sar                 eax, 4
            //   59                   | pop                 ecx

        $sequence_3 = { 75e9 e9???????? 33c0 38954feeffff 0f8426000000 8d9b00000000 0fb78884364100 }
            // n = 7, score = 200
            //   75e9                 | jne                 0xffffffeb
            //   e9????????           |                     
            //   33c0                 | xor                 eax, eax
            //   38954feeffff         | cmp                 byte ptr [ebp - 0x11b1], dl
            //   0f8426000000         | je                  0x2c
            //   8d9b00000000         | lea                 ebx, dword ptr [ebx]
            //   0fb78884364100       | movzx               ecx, word ptr [eax + 0x413684]

        $sequence_4 = { 3bf2 7ee5 68???????? e8???????? }
            // n = 4, score = 200
            //   3bf2                 | cmp                 esi, edx
            //   7ee5                 | jle                 0xffffffe7
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_5 = { 33f6 a1???????? 8b0d???????? 8b15???????? 8985a8f9ffff 8d85bcf9ffff }
            // n = 6, score = 200
            //   33f6                 | xor                 esi, esi
            //   a1????????           |                     
            //   8b0d????????         |                     
            //   8b15????????         |                     
            //   8985a8f9ffff         | mov                 dword ptr [ebp - 0x658], eax
            //   8d85bcf9ffff         | lea                 eax, dword ptr [ebp - 0x644]

        $sequence_6 = { 88500a 8d85e0fdffff 68???????? 50 e8???????? 8bf0 83c408 }
            // n = 7, score = 200
            //   88500a               | mov                 byte ptr [eax + 0xa], dl
            //   8d85e0fdffff         | lea                 eax, dword ptr [ebp - 0x220]
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c408               | add                 esp, 8

        $sequence_7 = { 47 ebd7 8b8dd8fbffff c6043900 53 ff15???????? ff15???????? }
            // n = 7, score = 200
            //   47                   | inc                 edi
            //   ebd7                 | jmp                 0xffffffd9
            //   8b8dd8fbffff         | mov                 ecx, dword ptr [ebp - 0x428]
            //   c6043900             | mov                 byte ptr [ecx + edi], 0
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   ff15????????         |                     

        $sequence_8 = { ffd7 56 ffd7 8b958cf9ffff 52 e8???????? 5f }
            // n = 7, score = 200
            //   ffd7                 | call                edi
            //   56                   | push                esi
            //   ffd7                 | call                edi
            //   8b958cf9ffff         | mov                 edx, dword ptr [ebp - 0x674]
            //   52                   | push                edx
            //   e8????????           |                     
            //   5f                   | pop                 edi

        $sequence_9 = { 50 8d95fcfdffff 6a02 52 }
            // n = 4, score = 200
            //   50                   | push                eax
            //   8d95fcfdffff         | lea                 edx, dword ptr [ebp - 0x204]
            //   6a02                 | push                2
            //   52                   | push                edx

    condition:
        7 of them and filesize < 425984
}