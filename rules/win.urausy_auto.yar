rule win_urausy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.urausy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.urausy"
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
        $sequence_0 = { ff35???????? 682c010000 ff7508 6a19 }
            // n = 4, score = 200
            //   ff35????????         |                     
            //   682c010000           | push                0x12c
            //   ff7508               | push                dword ptr [ebp + 8]
            //   6a19                 | push                0x19

        $sequence_1 = { 8bd8 56 56 68???????? 8d8500faffff 50 }
            // n = 6, score = 200
            //   8bd8                 | mov                 ebx, eax
            //   56                   | push                esi
            //   56                   | push                esi
            //   68????????           |                     
            //   8d8500faffff         | lea                 eax, dword ptr [ebp - 0x600]
            //   50                   | push                eax

        $sequence_2 = { 59 41 e9???????? 68007f0000 }
            // n = 4, score = 200
            //   59                   | pop                 ecx
            //   41                   | inc                 ecx
            //   e9????????           |                     
            //   68007f0000           | push                0x7f00

        $sequence_3 = { ff75a0 e8???????? 68d2070000 ff35???????? e8???????? a3???????? ff35???????? }
            // n = 7, score = 200
            //   ff75a0               | push                dword ptr [ebp - 0x60]
            //   e8????????           |                     
            //   68d2070000           | push                0x7d2
            //   ff35????????         |                     
            //   e8????????           |                     
            //   a3????????           |                     
            //   ff35????????         |                     

        $sequence_4 = { ff7508 6a14 68c8000000 ff75e4 ff75e8 6800000050 }
            // n = 6, score = 200
            //   ff7508               | push                dword ptr [ebp + 8]
            //   6a14                 | push                0x14
            //   68c8000000           | push                0xc8
            //   ff75e4               | push                dword ptr [ebp - 0x1c]
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   6800000050           | push                0x50000000

        $sequence_5 = { ff75ec e8???????? 5b 58 83c001 83c301 8bc8 }
            // n = 7, score = 200
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   e8????????           |                     
            //   5b                   | pop                 ebx
            //   58                   | pop                 eax
            //   83c001               | add                 eax, 1
            //   83c301               | add                 ebx, 1
            //   8bc8                 | mov                 ecx, eax

        $sequence_6 = { ff35???????? 8d8500fcffff 50 68???????? 8d8500ecffff 50 e8???????? }
            // n = 7, score = 200
            //   ff35????????         |                     
            //   8d8500fcffff         | lea                 eax, dword ptr [ebp - 0x400]
            //   50                   | push                eax
            //   68????????           |                     
            //   8d8500ecffff         | lea                 eax, dword ptr [ebp - 0x1400]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_7 = { ffb538edffff ff75ec e8???????? a1???????? }
            // n = 4, score = 200
            //   ffb538edffff         | push                dword ptr [ebp - 0x12c8]
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   e8????????           |                     
            //   a1????????           |                     

        $sequence_8 = { 6a00 ff35???????? 6896000000 ff7508 6a14 6a73 }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   ff35????????         |                     
            //   6896000000           | push                0x96
            //   ff7508               | push                dword ptr [ebp + 8]
            //   6a14                 | push                0x14
            //   6a73                 | push                0x73

        $sequence_9 = { 83c4dc 837d0800 750d 6a57 e8???????? 33c0 c9 }
            // n = 7, score = 200
            //   83c4dc               | add                 esp, -0x24
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   750d                 | jne                 0xf
            //   6a57                 | push                0x57
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   c9                   | leave               

    condition:
        7 of them and filesize < 98304
}