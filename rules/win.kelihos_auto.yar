rule win_kelihos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.kelihos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kelihos"
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
        $sequence_0 = { e8???????? 53 6a01 8bcf e8???????? 8b4508 e8???????? }
            // n = 7, score = 300
            //   e8????????           |                     
            //   53                   | push                ebx
            //   6a01                 | push                1
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   e8????????           |                     

        $sequence_1 = { c3 33c0 40 5b c3 33d2 56 }
            // n = 7, score = 300
            //   c3                   | ret                 
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   33d2                 | xor                 edx, edx
            //   56                   | push                esi

        $sequence_2 = { e8???????? 807c241300 8d4c2424 0f85a6feffff e8???????? 8d44242c 50 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   807c241300           | cmp                 byte ptr [esp + 0x13], 0
            //   8d4c2424             | lea                 ecx, dword ptr [esp + 0x24]
            //   0f85a6feffff         | jne                 0xfffffeac
            //   e8????????           |                     
            //   8d44242c             | lea                 eax, dword ptr [esp + 0x2c]
            //   50                   | push                eax

        $sequence_3 = { c21400 55 8bec 51 51 8b4704 53 }
            // n = 7, score = 300
            //   c21400               | ret                 0x14
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   8b4704               | mov                 eax, dword ptr [edi + 4]
            //   53                   | push                ebx

        $sequence_4 = { e8???????? 8d44247c e8???????? 8d44242c e8???????? 53 6a01 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   8d44247c             | lea                 eax, dword ptr [esp + 0x7c]
            //   e8????????           |                     
            //   8d44242c             | lea                 eax, dword ptr [esp + 0x2c]
            //   e8????????           |                     
            //   53                   | push                ebx
            //   6a01                 | push                1

        $sequence_5 = { ebab 74a7 33c0 c20400 55 8bec 51 }
            // n = 7, score = 300
            //   ebab                 | jmp                 0xffffffad
            //   74a7                 | je                  0xffffffa9
            //   33c0                 | xor                 eax, eax
            //   c20400               | ret                 4
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx

        $sequence_6 = { e8???????? 53 56 e9???????? 53 8d4d80 897d98 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   53                   | push                ebx
            //   56                   | push                esi
            //   e9????????           |                     
            //   53                   | push                ebx
            //   8d4d80               | lea                 ecx, dword ptr [ebp - 0x80]
            //   897d98               | mov                 dword ptr [ebp - 0x68], edi

        $sequence_7 = { c70054000000 89780c 833a00 8bce 740c 90 8b0a }
            // n = 7, score = 300
            //   c70054000000         | mov                 dword ptr [eax], 0x54
            //   89780c               | mov                 dword ptr [eax + 0xc], edi
            //   833a00               | cmp                 dword ptr [edx], 0
            //   8bce                 | mov                 ecx, esi
            //   740c                 | je                  0xe
            //   90                   | nop                 
            //   8b0a                 | mov                 ecx, dword ptr [edx]

        $sequence_8 = { ffd3 8d442410 50 6819000200 6a00 68c0160110 6802000080 }
            // n = 7, score = 300
            //   ffd3                 | call                ebx
            //   8d442410             | lea                 eax, dword ptr [esp + 0x10]
            //   50                   | push                eax
            //   6819000200           | push                0x20019
            //   6a00                 | push                0
            //   68c0160110           | push                0x100116c0
            //   6802000080           | push                0x80000002

        $sequence_9 = { e8???????? 894508 e8???????? 8bf0 8b4508 83c020 50 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83c020               | add                 eax, 0x20
            //   50                   | push                eax

    condition:
        7 of them and filesize < 4702208
}