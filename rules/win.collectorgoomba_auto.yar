rule win_collectorgoomba_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.collectorgoomba."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.collectorgoomba"
        malpedia_rule_date = "20220513"
        malpedia_hash = "7f4b2229e6ae614d86d74917f6d5b41890e62a26"
        malpedia_version = "20220516"
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
        $sequence_0 = { 89853cfeffff 8b853cfeffff 898538feffff c645fc3b ffb538feffff 8d8d48fdffff e8???????? }
            // n = 7, score = 200
            //   89853cfeffff         | mov                 dword ptr [ebp - 0x1c4], eax
            //   8b853cfeffff         | mov                 eax, dword ptr [ebp - 0x1c4]
            //   898538feffff         | mov                 dword ptr [ebp - 0x1c8], eax
            //   c645fc3b             | mov                 byte ptr [ebp - 4], 0x3b
            //   ffb538feffff         | push                dword ptr [ebp - 0x1c8]
            //   8d8d48fdffff         | lea                 ecx, [ebp - 0x2b8]
            //   e8????????           |                     

        $sequence_1 = { ff7508 e8???????? 83c40c ff75e8 e8???????? 59 ff75c8 }
            // n = 7, score = 200
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   ff75c8               | push                dword ptr [ebp - 0x38]

        $sequence_2 = { eb04 834df4ff 837dec6c 7536 c645df01 8b4510 40 }
            // n = 7, score = 200
            //   eb04                 | jmp                 6
            //   834df4ff             | or                  dword ptr [ebp - 0xc], 0xffffffff
            //   837dec6c             | cmp                 dword ptr [ebp - 0x14], 0x6c
            //   7536                 | jne                 0x38
            //   c645df01             | mov                 byte ptr [ebp - 0x21], 1
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   40                   | inc                 eax

        $sequence_3 = { 8d859cfeffff 50 8d8dc8feffff e8???????? 8b00 894590 8b4590 }
            // n = 7, score = 200
            //   8d859cfeffff         | lea                 eax, [ebp - 0x164]
            //   50                   | push                eax
            //   8d8dc8feffff         | lea                 ecx, [ebp - 0x138]
            //   e8????????           |                     
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   894590               | mov                 dword ptr [ebp - 0x70], eax
            //   8b4590               | mov                 eax, dword ptr [ebp - 0x70]

        $sequence_4 = { 8b85b8fcffff 8985b4fcffff c645fc35 8b85b4fcffff 8985acfcffff ffb5b0fcffff ffb5acfcffff }
            // n = 7, score = 200
            //   8b85b8fcffff         | mov                 eax, dword ptr [ebp - 0x348]
            //   8985b4fcffff         | mov                 dword ptr [ebp - 0x34c], eax
            //   c645fc35             | mov                 byte ptr [ebp - 4], 0x35
            //   8b85b4fcffff         | mov                 eax, dword ptr [ebp - 0x34c]
            //   8985acfcffff         | mov                 dword ptr [ebp - 0x354], eax
            //   ffb5b0fcffff         | push                dword ptr [ebp - 0x350]
            //   ffb5acfcffff         | push                dword ptr [ebp - 0x354]

        $sequence_5 = { e9???????? ff75e8 ff7508 e8???????? 59 59 8b45e8 }
            // n = 7, score = 200
            //   e9????????           |                     
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]

        $sequence_6 = { ff700c ff7508 e8???????? 83c410 e9???????? ff75f4 e8???????? }
            // n = 7, score = 200
            //   ff700c               | push                dword ptr [eax + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   e9????????           |                     
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   e8????????           |                     

        $sequence_7 = { ff7014 ff75ec 6a0c ff75fc e8???????? 83c41c 8b45e8 }
            // n = 7, score = 200
            //   ff7014               | push                dword ptr [eax + 0x14]
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   6a0c                 | push                0xc
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   83c41c               | add                 esp, 0x1c
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]

        $sequence_8 = { c705????????0e040602 c705????????0106010c 833d????????00 740a c705????????040a0e0b c705????????0d0d020f c705????????0f0f0109 }
            // n = 7, score = 200
            //   c705????????0e040602     |     
            //   c705????????0106010c     |     
            //   833d????????00       |                     
            //   740a                 | je                  0xc
            //   c705????????040a0e0b     |     
            //   c705????????0d0d020f     |     
            //   c705????????0f0f0109     |     

        $sequence_9 = { eb18 8b4508 0fb74042 8945f4 8b45f4 3b45fc 7606 }
            // n = 7, score = 200
            //   eb18                 | jmp                 0x1a
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   0fb74042             | movzx               eax, word ptr [eax + 0x42]
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   3b45fc               | cmp                 eax, dword ptr [ebp - 4]
            //   7606                 | jbe                 8

    condition:
        7 of them and filesize < 1400832
}