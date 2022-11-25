rule win_pgift_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.pgift."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pgift"
        malpedia_rule_date = "20221118"
        malpedia_hash = "e0702e2e6d1d00da65c8a29a4ebacd0a4c59e1af"
        malpedia_version = "20221125"
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
        $sequence_0 = { 6800000040 ff75ec ffd6 83f8ff 8945f0 0f8494000000 }
            // n = 6, score = 100
            //   6800000040           | push                0x40000000
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   ffd6                 | call                esi
            //   83f8ff               | cmp                 eax, -1
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   0f8494000000         | je                  0x9a

        $sequence_1 = { 7ce4 33c0 5f 5e c3 8b04fdac640010 }
            // n = 6, score = 100
            //   7ce4                 | jl                  0xffffffe6
            //   33c0                 | xor                 eax, eax
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   8b04fdac640010       | mov                 eax, dword ptr [edi*8 + 0x100064ac]

        $sequence_2 = { ff7510 8bcb e8???????? 83c304 ebed 8b450c 014608 }
            // n = 7, score = 100
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   83c304               | add                 ebx, 4
            //   ebed                 | jmp                 0xffffffef
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   014608               | add                 dword ptr [esi + 8], eax

        $sequence_3 = { 8d4dec c645fc03 e8???????? ff7510 8d4de8 e8???????? 8d4dec }
            // n = 7, score = 100
            //   8d4dec               | lea                 ecx, [ebp - 0x14]
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3
            //   e8????????           |                     
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   8d4de8               | lea                 ecx, [ebp - 0x18]
            //   e8????????           |                     
            //   8d4dec               | lea                 ecx, [ebp - 0x14]

        $sequence_4 = { ff7638 8bce ff7630 e8???????? 57 8bce }
            // n = 6, score = 100
            //   ff7638               | push                dword ptr [esi + 0x38]
            //   8bce                 | mov                 ecx, esi
            //   ff7630               | push                dword ptr [esi + 0x30]
            //   e8????????           |                     
            //   57                   | push                edi
            //   8bce                 | mov                 ecx, esi

        $sequence_5 = { 8d4de8 c645fc01 e8???????? 83f8ff 750f 6a2f }
            // n = 6, score = 100
            //   8d4de8               | lea                 ecx, [ebp - 0x18]
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   e8????????           |                     
            //   83f8ff               | cmp                 eax, -1
            //   750f                 | jne                 0x11
            //   6a2f                 | push                0x2f

        $sequence_6 = { 7504 33c0 eb08 8b4708 2bc2 c1f802 8b5e04 }
            // n = 7, score = 100
            //   7504                 | jne                 6
            //   33c0                 | xor                 eax, eax
            //   eb08                 | jmp                 0xa
            //   8b4708               | mov                 eax, dword ptr [edi + 8]
            //   2bc2                 | sub                 eax, edx
            //   c1f802               | sar                 eax, 2
            //   8b5e04               | mov                 ebx, dword ptr [esi + 4]

        $sequence_7 = { 8d4df0 c645fc01 e8???????? 8b4624 c645fc02 3bc3 743c }
            // n = 7, score = 100
            //   8d4df0               | lea                 ecx, [ebp - 0x10]
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   e8????????           |                     
            //   8b4624               | mov                 eax, dword ptr [esi + 0x24]
            //   c645fc02             | mov                 byte ptr [ebp - 4], 2
            //   3bc3                 | cmp                 eax, ebx
            //   743c                 | je                  0x3e

        $sequence_8 = { 50 e8???????? 8d7e01 57 ebac 8d450c 57 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d7e01               | lea                 edi, [esi + 1]
            //   57                   | push                edi
            //   ebac                 | jmp                 0xffffffae
            //   8d450c               | lea                 eax, [ebp + 0xc]
            //   57                   | push                edi

        $sequence_9 = { 83ef04 83eb04 57 8bcb }
            // n = 4, score = 100
            //   83ef04               | sub                 edi, 4
            //   83eb04               | sub                 ebx, 4
            //   57                   | push                edi
            //   8bcb                 | mov                 ecx, ebx

    condition:
        7 of them and filesize < 98304
}