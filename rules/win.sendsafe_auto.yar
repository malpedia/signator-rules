rule win_sendsafe_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.sendsafe."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sendsafe"
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
        $sequence_0 = { e8???????? 83c404 8985f8fbffff 83bdf8fbffff00 0f84e8000000 33c9 8b85f8fbffff }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8985f8fbffff         | mov                 dword ptr [ebp - 0x408], eax
            //   83bdf8fbffff00       | cmp                 dword ptr [ebp - 0x408], 0
            //   0f84e8000000         | je                  0xee
            //   33c9                 | xor                 ecx, ecx
            //   8b85f8fbffff         | mov                 eax, dword ptr [ebp - 0x408]

        $sequence_1 = { e8???????? c745fc00000000 8b45e8 83c018 8945ec 8b4dec c70100000000 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   83c018               | add                 eax, 0x18
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   c70100000000         | mov                 dword ptr [ecx], 0

        $sequence_2 = { e9???????? 8b45e8 83c018 50 8b4d08 51 8b5508 }
            // n = 7, score = 200
            //   e9????????           |                     
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   83c018               | add                 eax, 0x18
            //   50                   | push                eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   51                   | push                ecx
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]

        $sequence_3 = { e8???????? 83c410 81bda8fdffffffffff7f 7628 68ffffff7f 8b85a8fdffff 50 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   81bda8fdffffffffff7f     | cmp    dword ptr [ebp - 0x258], 0x7fffffff
            //   7628                 | jbe                 0x2a
            //   68ffffff7f           | push                0x7fffffff
            //   8b85a8fdffff         | mov                 eax, dword ptr [ebp - 0x258]
            //   50                   | push                eax

        $sequence_4 = { 8b55fc c7423800000000 8b45fc 8b4dfc 8b5108 895020 c745f800000000 }
            // n = 7, score = 200
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   c7423800000000       | mov                 dword ptr [edx + 0x38], 0
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8b5108               | mov                 edx, dword ptr [ecx + 8]
            //   895020               | mov                 dword ptr [eax + 0x20], edx
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0

        $sequence_5 = { e9???????? 8b5514 8955fc eb09 8b45fc 83c001 8945fc }
            // n = 7, score = 200
            //   e9????????           |                     
            //   8b5514               | mov                 edx, dword ptr [ebp + 0x14]
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   eb09                 | jmp                 0xb
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   83c001               | add                 eax, 1
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_6 = { e8???????? 83c418 e9???????? 55 e8???????? 68b40b0000 ebd8 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   e9????????           |                     
            //   55                   | push                ebp
            //   e8????????           |                     
            //   68b40b0000           | push                0xbb4
            //   ebd8                 | jmp                 0xffffffda

        $sequence_7 = { ba02000000 c1e200 8b45f0 668b4dc8 66890c10 ba02000000 d1e2 }
            // n = 7, score = 200
            //   ba02000000           | mov                 edx, 2
            //   c1e200               | shl                 edx, 0
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   668b4dc8             | mov                 cx, word ptr [ebp - 0x38]
            //   66890c10             | mov                 word ptr [eax + edx], cx
            //   ba02000000           | mov                 edx, 2
            //   d1e2                 | shl                 edx, 1

        $sequence_8 = { 8b5508 8b45fc 8b481c 898af8000000 8b5508 8b45fc 8b4820 }
            // n = 7, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b481c               | mov                 ecx, dword ptr [eax + 0x1c]
            //   898af8000000         | mov                 dword ptr [edx + 0xf8], ecx
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b4820               | mov                 ecx, dword ptr [eax + 0x20]

        $sequence_9 = { e8???????? 83c40c 85c0 0f8595010000 ff742448 ff742448 e8???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   0f8595010000         | jne                 0x19b
            //   ff742448             | push                dword ptr [esp + 0x48]
            //   ff742448             | push                dword ptr [esp + 0x48]
            //   e8????????           |                     

    condition:
        7 of them and filesize < 3743744
}