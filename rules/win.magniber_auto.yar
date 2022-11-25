rule win_magniber_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.magniber."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.magniber"
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
        $sequence_0 = { c78508fdffff20994000 c7850cfdffff28994000 c78510fdffff30994000 c78514fdffff38994000 }
            // n = 4, score = 400
            //   c78508fdffff20994000     | mov    dword ptr [ebp - 0x2f8], 0x409920
            //   c7850cfdffff28994000     | mov    dword ptr [ebp - 0x2f4], 0x409928
            //   c78510fdffff30994000     | mov    dword ptr [ebp - 0x2f0], 0x409930
            //   c78514fdffff38994000     | mov    dword ptr [ebp - 0x2ec], 0x409938

        $sequence_1 = { 8b5508 52 8d85fcfbffff 50 ff15???????? }
            // n = 5, score = 400
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   52                   | push                edx
            //   8d85fcfbffff         | lea                 eax, [ebp - 0x404]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_2 = { c7853cfaffff18934000 c78540faffff20934000 c78544faffff28934000 c78548faffff30934000 }
            // n = 4, score = 400
            //   c7853cfaffff18934000     | mov    dword ptr [ebp - 0x5c4], 0x409318
            //   c78540faffff20934000     | mov    dword ptr [ebp - 0x5c0], 0x409320
            //   c78544faffff28934000     | mov    dword ptr [ebp - 0x5bc], 0x409328
            //   c78548faffff30934000     | mov    dword ptr [ebp - 0x5b8], 0x409330

        $sequence_3 = { 83e802 69c07c030000 0345e4 50 e8???????? 83c40c }
            // n = 6, score = 400
            //   83e802               | sub                 eax, 2
            //   69c07c030000         | imul                eax, eax, 0x37c
            //   0345e4               | add                 eax, dword ptr [ebp - 0x1c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_4 = { 55 8bec 51 8b4508 83b86804000000 }
            // n = 5, score = 400
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83b86804000000       | cmp                 dword ptr [eax + 0x468], 0

        $sequence_5 = { 52 ff15???????? 85c0 0f848b000000 8b4594 3b45bc 7c4c }
            // n = 7, score = 400
            //   52                   | push                edx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f848b000000         | je                  0x91
            //   8b4594               | mov                 eax, dword ptr [ebp - 0x6c]
            //   3b45bc               | cmp                 eax, dword ptr [ebp - 0x44]
            //   7c4c                 | jl                  0x4e

        $sequence_6 = { 8945f8 33c9 8b55f8 66890a 8b45fc 50 }
            // n = 6, score = 400
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   33c9                 | xor                 ecx, ecx
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   66890a               | mov                 word ptr [edx], cx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax

        $sequence_7 = { 33c0 e9???????? 6874040000 6a00 }
            // n = 4, score = 400
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   6874040000           | push                0x474
            //   6a00                 | push                0

        $sequence_8 = { 4834b0 184026 e221 a1????????05eef081 e0f8 29aed0515fa6 8d4f0e }
            // n = 7, score = 100
            //   4834b0               | dec                 eax
            //   184026               | xor                 al, 0xb0
            //   e221                 | sbb                 byte ptr [eax + 0x26], al
            //   a1????????05eef081     |     
            //   e0f8                 | loop                0x23
            //   29aed0515fa6         | loopne              0xfffffffa
            //   8d4f0e               | sub                 dword ptr [esi - 0x59a0ae30], ebp

        $sequence_9 = { d331 4e4e54 70ac 52 }
            // n = 4, score = 100
            //   d331                 | and                 dword ptr [esp + ebp*2 + 0x2e], esi
            //   4e4e54               | loop                0x23
            //   70ac                 | loopne              0xfffffffa
            //   52                   | sub                 dword ptr [esi - 0x59a0ae30], ebp

        $sequence_10 = { 18cb 52 fc 285f44 }
            // n = 4, score = 100
            //   18cb                 | mov                 dh, 0x36
            //   52                   | sbb                 bl, cl
            //   fc                   | push                edx
            //   285f44               | cld                 

        $sequence_11 = { b3b1 3e6c 21746c2e 4834b0 184026 }
            // n = 5, score = 100
            //   b3b1                 | sub                 byte ptr [edi + 0x44], bl
            //   3e6c                 | mov                 bl, 0xb1
            //   21746c2e             | insb                byte ptr es:[edi], dx
            //   4834b0               | and                 dword ptr [esp + ebp*2 + 0x2e], esi
            //   184026               | dec                 eax

        $sequence_12 = { fc 285f44 c1c70d 11fb }
            // n = 4, score = 100
            //   fc                   | xor                 al, 0xb0
            //   285f44               | sbb                 byte ptr [eax + 0x26], al
            //   c1c70d               | loop                0x23
            //   11fb                 | xor                 cl, bl

        $sequence_13 = { 8d4f0e 7f4c c82cd1c6 1a32 b636 }
            // n = 5, score = 100
            //   8d4f0e               | lea                 ecx, [edi + 0xe]
            //   7f4c                 | lea                 ecx, [edi + 0xe]
            //   c82cd1c6             | jg                  0x4e
            //   1a32                 | enter               -0x2ed4, -0x3a
            //   b636                 | sbb                 dh, byte ptr [edx]

        $sequence_14 = { e8???????? 32cb 5a b3b1 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   32cb                 | loopne              0xfffffffa
            //   5a                   | sub                 dword ptr [esi - 0x59a0ae30], ebp
            //   b3b1                 | lea                 ecx, [edi + 0xe]

        $sequence_15 = { 70ac 52 f8 a6 }
            // n = 4, score = 100
            //   70ac                 | jo                  0xffffffae
            //   52                   | push                edx
            //   f8                   | clc                 
            //   a6                   | cmpsb               byte ptr [esi], byte ptr es:[edi]

    condition:
        7 of them and filesize < 117760
}