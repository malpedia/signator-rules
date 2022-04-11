rule win_miragefox_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.miragefox."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.miragefox"
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
        $sequence_0 = { 8d4604 6a19 50 57 e8???????? }
            // n = 5, score = 100
            //   8d4604               | lea                 eax, dword ptr [esi + 4]
            //   6a19                 | push                0x19
            //   50                   | push                eax
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_1 = { ff2485b9902900 33c0 834df8ff 8945c0 }
            // n = 4, score = 100
            //   ff2485b9902900       | jmp                 dword ptr [eax*4 + 0x2990b9]
            //   33c0                 | xor                 eax, eax
            //   834df8ff             | or                  dword ptr [ebp - 8], 0xffffffff
            //   8945c0               | mov                 dword ptr [ebp - 0x40], eax

        $sequence_2 = { ebc3 b8???????? c3 b8???????? e8???????? b85c840000 e8???????? }
            // n = 7, score = 100
            //   ebc3                 | jmp                 0xffffffc5
            //   b8????????           |                     
            //   c3                   | ret                 
            //   b8????????           |                     
            //   e8????????           |                     
            //   b85c840000           | mov                 eax, 0x845c
            //   e8????????           |                     

        $sequence_3 = { b85c840000 e8???????? 53 8b5d08 56 57 6a09 }
            // n = 7, score = 100
            //   b85c840000           | mov                 eax, 0x845c
            //   e8????????           |                     
            //   53                   | push                ebx
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   56                   | push                esi
            //   57                   | push                edi
            //   6a09                 | push                9

        $sequence_4 = { 304e29 005c4e29 00804e290023 d18a0688078a }
            // n = 4, score = 100
            //   304e29               | xor                 byte ptr [esi + 0x29], cl
            //   005c4e29             | add                 byte ptr [esi + ecx*2 + 0x29], bl
            //   00804e290023         | add                 byte ptr [eax + 0x2300294e], al
            //   d18a0688078a         | ror                 dword ptr [edx - 0x75f877fa], 1

        $sequence_5 = { eb1b 8b4514 f6c303 7509 8b0c85c05e2a00 eb07 8b0c85f45e2a00 }
            // n = 7, score = 100
            //   eb1b                 | jmp                 0x1d
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   f6c303               | test                bl, 3
            //   7509                 | jne                 0xb
            //   8b0c85c05e2a00       | mov                 ecx, dword ptr [eax*4 + 0x2a5ec0]
            //   eb07                 | jmp                 9
            //   8b0c85f45e2a00       | mov                 ecx, dword ptr [eax*4 + 0x2a5ef4]

        $sequence_6 = { 8d85acfcffff 50 e8???????? 59 59 e8???????? be???????? }
            // n = 7, score = 100
            //   8d85acfcffff         | lea                 eax, dword ptr [ebp - 0x354]
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   e8????????           |                     
            //   be????????           |                     

        $sequence_7 = { 8885ec7fffff 8d85e0f7feff 50 e8???????? }
            // n = 4, score = 100
            //   8885ec7fffff         | mov                 byte ptr [ebp - 0x8014], al
            //   8d85e0f7feff         | lea                 eax, dword ptr [ebp - 0x10820]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_8 = { 0fb6da f68341f72a0004 7406 8816 }
            // n = 4, score = 100
            //   0fb6da               | movzx               ebx, dl
            //   f68341f72a0004       | test                byte ptr [ebx + 0x2af741], 4
            //   7406                 | je                  8
            //   8816                 | mov                 byte ptr [esi], dl

        $sequence_9 = { 8d45f4 50 6819000200 56 68???????? 6801000080 ff15???????? }
            // n = 7, score = 100
            //   8d45f4               | lea                 eax, dword ptr [ebp - 0xc]
            //   50                   | push                eax
            //   6819000200           | push                0x20019
            //   56                   | push                esi
            //   68????????           |                     
            //   6801000080           | push                0x80000001
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 286720
}