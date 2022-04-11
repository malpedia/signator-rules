rule win_unidentified_053_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.unidentified_053."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_053"
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
        $sequence_0 = { 06 7166 04f7 82198d 12b30be957e6 9b }
            // n = 6, score = 100
            //   06                   | push                es
            //   7166                 | jno                 0x68
            //   04f7                 | add                 al, 0xf7
            //   82198d               |                     
            //   12b30be957e6         | adc                 dh, byte ptr [ebx - 0x19a816f5]
            //   9b                   | wait                

        $sequence_1 = { 33c1 e8???????? f7d6 03d9 47 4f 2bd9 }
            // n = 7, score = 100
            //   33c1                 | xor                 eax, ecx
            //   e8????????           |                     
            //   f7d6                 | not                 esi
            //   03d9                 | add                 ebx, ecx
            //   47                   | inc                 edi
            //   4f                   | dec                 edi
            //   2bd9                 | sub                 ebx, ecx

        $sequence_2 = { e8???????? ff75f0 e9???????? 8b4508 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   e9????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_3 = { 8a6e2d 8a4e2c c1e108 0bca }
            // n = 4, score = 100
            //   8a6e2d               | mov                 ch, byte ptr [esi + 0x2d]
            //   8a4e2c               | mov                 cl, byte ptr [esi + 0x2c]
            //   c1e108               | shl                 ecx, 8
            //   0bca                 | or                  ecx, edx

        $sequence_4 = { ff513c 85c0 0f851f010000 85db 7532 ff75f4 e8???????? }
            // n = 7, score = 100
            //   ff513c               | call                dword ptr [ecx + 0x3c]
            //   85c0                 | test                eax, eax
            //   0f851f010000         | jne                 0x125
            //   85db                 | test                ebx, ebx
            //   7532                 | jne                 0x34
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   e8????????           |                     

        $sequence_5 = { 56 8d34c0 8d1c9d40964100 8b03 c1e602 f644300420 }
            // n = 6, score = 100
            //   56                   | push                esi
            //   8d34c0               | lea                 esi, dword ptr [eax + eax*8]
            //   8d1c9d40964100       | lea                 ebx, dword ptr [ebx*4 + 0x419640]
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   c1e602               | shl                 esi, 2
            //   f644300420           | test                byte ptr [eax + esi + 4], 0x20

        $sequence_6 = { 0fb67df4 8a4e1a 0fb65df2 c1e108 0bc8 }
            // n = 5, score = 100
            //   0fb67df4             | movzx               edi, byte ptr [ebp - 0xc]
            //   8a4e1a               | mov                 cl, byte ptr [esi + 0x1a]
            //   0fb65df2             | movzx               ebx, byte ptr [ebp - 0xe]
            //   c1e108               | shl                 ecx, 8
            //   0bc8                 | or                  ecx, eax

        $sequence_7 = { 81ea003145d4 81ee81deeb08 f7de 891d???????? c1c606 f7d6 }
            // n = 6, score = 100
            //   81ea003145d4         | sub                 edx, 0xd4453100
            //   81ee81deeb08         | sub                 esi, 0x8ebde81
            //   f7de                 | neg                 esi
            //   891d????????         |                     
            //   c1c606               | rol                 esi, 6
            //   f7d6                 | not                 esi

        $sequence_8 = { 03f7 46 f7d8 81ebd4b243e9 c1c80c }
            // n = 5, score = 100
            //   03f7                 | add                 esi, edi
            //   46                   | inc                 esi
            //   f7d8                 | neg                 eax
            //   81ebd4b243e9         | sub                 ebx, 0xe943b2d4
            //   c1c80c               | ror                 eax, 0xc

        $sequence_9 = { 46 8a11 0fb6fa 41 f6870194410004 }
            // n = 5, score = 100
            //   46                   | inc                 esi
            //   8a11                 | mov                 dl, byte ptr [ecx]
            //   0fb6fa               | movzx               edi, dl
            //   41                   | inc                 ecx
            //   f6870194410004       | test                byte ptr [edi + 0x419401], 4

    condition:
        7 of them and filesize < 294912
}