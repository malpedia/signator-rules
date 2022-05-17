rule win_playwork_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.playwork."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.playwork"
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
        $sequence_0 = { 50 8d45fc ff7508 50 e8???????? }
            // n = 5, score = 100
            //   50                   | push                eax
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_1 = { 8b35???????? 5b 7405 ff75f0 ffd6 837de8ff 7405 }
            // n = 7, score = 100
            //   8b35????????         |                     
            //   5b                   | pop                 ebx
            //   7405                 | je                  7
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   ffd6                 | call                esi
            //   837de8ff             | cmp                 dword ptr [ebp - 0x18], -1
            //   7405                 | je                  7

        $sequence_2 = { 57 ff75fc ff15???????? 85c0 0f857e020000 8d45f0 c745f000100000 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f857e020000         | jne                 0x284
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   c745f000100000       | mov                 dword ptr [ebp - 0x10], 0x1000

        $sequence_3 = { b890150000 e8???????? 53 33db 391d???????? 56 57 }
            // n = 7, score = 100
            //   b890150000           | mov                 eax, 0x1590
            //   e8????????           |                     
            //   53                   | push                ebx
            //   33db                 | xor                 ebx, ebx
            //   391d????????         |                     
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_4 = { 83c418 8d858cfdffff 50 8d857cf9ffff 50 ff15???????? }
            // n = 6, score = 100
            //   83c418               | add                 esp, 0x18
            //   8d858cfdffff         | lea                 eax, [ebp - 0x274]
            //   50                   | push                eax
            //   8d857cf9ffff         | lea                 eax, [ebp - 0x684]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_5 = { c9 c3 ff15???????? ff35???????? ff15???????? c3 55 }
            // n = 7, score = 100
            //   c9                   | leave               
            //   c3                   | ret                 
            //   ff15????????         |                     
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   c3                   | ret                 
            //   55                   | push                ebp

        $sequence_6 = { 6808020000 8d85e4fcffff 53 50 e8???????? 6804010000 8d85ecfeffff }
            // n = 7, score = 100
            //   6808020000           | push                0x208
            //   8d85e4fcffff         | lea                 eax, [ebp - 0x31c]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   6804010000           | push                0x104
            //   8d85ecfeffff         | lea                 eax, [ebp - 0x114]

        $sequence_7 = { 834df8ff b800280000 50 8945f0 e8???????? 8bf8 59 }
            // n = 7, score = 100
            //   834df8ff             | or                  dword ptr [ebp - 8], 0xffffffff
            //   b800280000           | mov                 eax, 0x2800
            //   50                   | push                eax
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   59                   | pop                 ecx

        $sequence_8 = { 8944243c 8d84244c0c0000 50 e8???????? 8b9c2454640000 83c424 68???????? }
            // n = 7, score = 100
            //   8944243c             | mov                 dword ptr [esp + 0x3c], eax
            //   8d84244c0c0000       | lea                 eax, [esp + 0xc4c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b9c2454640000       | mov                 ebx, dword ptr [esp + 0x6454]
            //   83c424               | add                 esp, 0x24
            //   68????????           |                     

        $sequence_9 = { ff15???????? 8d855cfeffff 50 6802020000 ff15???????? 6880000000 bf???????? }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8d855cfeffff         | lea                 eax, [ebp - 0x1a4]
            //   50                   | push                eax
            //   6802020000           | push                0x202
            //   ff15????????         |                     
            //   6880000000           | push                0x80
            //   bf????????           |                     

    condition:
        7 of them and filesize < 360448
}