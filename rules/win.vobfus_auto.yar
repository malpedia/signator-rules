rule win_vobfus_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.vobfus."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vobfus"
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
        $sequence_0 = { 8b5508 8b92e8000000 8b82d00a0000 50 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b82d00a0000         | mov                 eax, dword ptr [edx + 0xad0]
            //   50                   | push                eax

        $sequence_1 = { 8b5508 8b92e8000000 8b8230200000 50 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b8230200000         | mov                 eax, dword ptr [edx + 0x2030]
            //   50                   | push                eax

        $sequence_2 = { 8bec 8b5508 8b92e8000000 8b82441b0000 50 }
            // n = 5, score = 200
            //   8bec                 | mov                 ebp, esp
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b82441b0000         | mov                 eax, dword ptr [edx + 0x1b44]
            //   50                   | push                eax

        $sequence_3 = { 8b92e8000000 8b82a40c0000 50 50 }
            // n = 4, score = 200
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b82a40c0000         | mov                 eax, dword ptr [edx + 0xca4]
            //   50                   | push                eax
            //   50                   | push                eax

        $sequence_4 = { 8b5508 8b92e8000000 8b827c1f0000 50 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b827c1f0000         | mov                 eax, dword ptr [edx + 0x1f7c]
            //   50                   | push                eax

        $sequence_5 = { 8b5508 8b92e8000000 8b82780e0000 50 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b82780e0000         | mov                 eax, dword ptr [edx + 0xe78]
            //   50                   | push                eax

        $sequence_6 = { 8b8230170000 50 50 8b10 }
            // n = 4, score = 200
            //   8b8230170000         | mov                 eax, dword ptr [edx + 0x1730]
            //   50                   | push                eax
            //   50                   | push                eax
            //   8b10                 | mov                 edx, dword ptr [eax]

        $sequence_7 = { 8b5508 8b92e8000000 8b82f0020000 50 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b82f0020000         | mov                 eax, dword ptr [edx + 0x2f0]
            //   50                   | push                eax

        $sequence_8 = { c1b8cc92aed3d4 9d 0e 06 ec 3bce }
            // n = 6, score = 100
            //   c1b8cc92aed3d4       | sar                 dword ptr [eax - 0x2c516d34], -0x2c
            //   9d                   | popfd               
            //   0e                   | push                cs
            //   06                   | push                es
            //   ec                   | in                  al, dx
            //   3bce                 | cmp                 ecx, esi

        $sequence_9 = { 058565e459 49 e278 8161d356b32dee 57 }
            // n = 5, score = 100
            //   058565e459           | add                 eax, 0x59e46585
            //   49                   | dec                 ecx
            //   e278                 | loop                0x7a
            //   8161d356b32dee       | and                 dword ptr [ecx - 0x2d], 0xee2db356
            //   57                   | push                edi

        $sequence_10 = { 56 a1???????? ec 54 3dae8602f8 }
            // n = 5, score = 100
            //   56                   | push                esi
            //   a1????????           |                     
            //   ec                   | in                  al, dx
            //   54                   | push                esp
            //   3dae8602f8           | cmp                 eax, 0xf80286ae

        $sequence_11 = { 8cc7 e752 47 625403a7 78f5 }
            // n = 5, score = 100
            //   8cc7                 | mov                 edi, es
            //   e752                 | out                 0x52, eax
            //   47                   | inc                 edi
            //   625403a7             | bound               edx, qword ptr [ebx + eax - 0x59]
            //   78f5                 | js                  0xfffffff7

        $sequence_12 = { 8f00 e3ce 97 00e6 d39500e4d19b 00cf }
            // n = 6, score = 100
            //   8f00                 | pop                 dword ptr [eax]
            //   e3ce                 | jecxz               0xffffffd0
            //   97                   | xchg                eax, edi
            //   00e6                 | add                 dh, ah
            //   d39500e4d19b         | rcl                 dword ptr [ebp - 0x642e1c00], cl
            //   00cf                 | add                 bh, cl

        $sequence_13 = { 3e3cff 46 14ff 0470 fe0a d6 }
            // n = 6, score = 100
            //   3e3cff               | cmp                 al, 0xff
            //   46                   | inc                 esi
            //   14ff                 | adc                 al, 0xff
            //   0470                 | add                 al, 0x70
            //   fe0a                 | dec                 byte ptr [edx]
            //   d6                   | salc                

        $sequence_14 = { bdb000d6c2 91 00d5 c19400d6c49500d7 c59900dac999 00e0 }
            // n = 6, score = 100
            //   bdb000d6c2           | mov                 ebp, 0xc2d600b0
            //   91                   | xchg                eax, ecx
            //   00d5                 | add                 ch, dl
            //   c19400d6c49500d7     | rcl                 dword ptr [eax + eax + 0x95c4d6], -0x29
            //   c59900dac999         | lds                 ebx, ptr [ecx - 0x66362600]
            //   00e0                 | add                 al, ah

        $sequence_15 = { 8907 6bdd97 d127 8b8ec9322003 26c1a5d9924bb222 56 a1???????? }
            // n = 7, score = 100
            //   8907                 | mov                 dword ptr [edi], eax
            //   6bdd97               | imul                ebx, ebp, -0x69
            //   d127                 | shl                 dword ptr [edi], 1
            //   8b8ec9322003         | mov                 ecx, dword ptr [esi + 0x32032c9]
            //   26c1a5d9924bb222     | shl                 dword ptr es:[ebp - 0x4db46d27], 0x22
            //   56                   | push                esi
            //   a1????????           |                     

        $sequence_16 = { f2e8fae6d5f6 d2b5f2bb8ff3 ae 73f3 aa }
            // n = 5, score = 100
            //   f2e8fae6d5f6         | bnd call            0xf6d5e700
            //   d2b5f2bb8ff3         | sal                 byte ptr [ebp - 0xc70440e], cl
            //   ae                   | scasb               al, byte ptr es:[edi]
            //   73f3                 | jae                 0xfffffff5
            //   aa                   | stosb               byte ptr es:[edi], al

        $sequence_17 = { 7cc8 dc7acd e291 d2e8 }
            // n = 4, score = 100
            //   7cc8                 | jl                  0xffffffca
            //   dc7acd               | fdivr               qword ptr [edx - 0x33]
            //   e291                 | loop                0xffffff93
            //   d2e8                 | shr                 al, cl

        $sequence_18 = { 1400 48 0008 78ff }
            // n = 4, score = 100
            //   1400                 | adc                 al, 0
            //   48                   | dec                 eax
            //   0008                 | add                 byte ptr [eax], cl
            //   78ff                 | js                  1

        $sequence_19 = { 0008 78ff 0d50004900 3e3cff 46 14ff }
            // n = 6, score = 100
            //   0008                 | add                 byte ptr [eax], cl
            //   78ff                 | js                  1
            //   0d50004900           | or                  eax, 0x490050
            //   3e3cff               | cmp                 al, 0xff
            //   46                   | inc                 esi
            //   14ff                 | adc                 al, 0xff

        $sequence_20 = { ec f2ed ec f3ed ebf2 ed }
            // n = 6, score = 100
            //   ec                   | in                  al, dx
            //   f2ed                 | in                  eax, dx
            //   ec                   | in                  al, dx
            //   f3ed                 | in                  eax, dx
            //   ebf2                 | jmp                 0xfffffff4
            //   ed                   | in                  eax, dx

        $sequence_21 = { ef 60 226aa3 60 8907 6bdd97 d127 }
            // n = 7, score = 100
            //   ef                   | out                 dx, eax
            //   60                   | pushal              
            //   226aa3               | and                 ch, byte ptr [edx - 0x5d]
            //   60                   | pushal              
            //   8907                 | mov                 dword ptr [edi], eax
            //   6bdd97               | imul                ebx, ebp, -0x69
            //   d127                 | shl                 dword ptr [edi], 1

        $sequence_22 = { 73f3 aa 5c f6ac4ff8b54ffb c058fcca }
            // n = 5, score = 100
            //   73f3                 | jae                 0xfffffff5
            //   aa                   | stosb               byte ptr es:[edi], al
            //   5c                   | pop                 esp
            //   f6ac4ff8b54ffb       | imul                byte ptr [edi + ecx*2 - 0x4b04a08]
            //   c058fcca             | rcr                 byte ptr [eax - 4], 0xca

        $sequence_23 = { f2ed ec f2ed ec f2ed ec f2ed }
            // n = 7, score = 100
            //   f2ed                 | in                  eax, dx
            //   ec                   | in                  al, dx
            //   f2ed                 | in                  eax, dx
            //   ec                   | in                  al, dx
            //   f2ed                 | in                  eax, dx
            //   ec                   | in                  al, dx
            //   f2ed                 | in                  eax, dx

    condition:
        7 of them and filesize < 409600
}