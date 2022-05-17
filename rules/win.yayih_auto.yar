rule win_yayih_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.yayih."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.yayih"
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
        $sequence_0 = { e9???????? 6a64 ff15???????? 3975e8 7435 }
            // n = 5, score = 100
            //   e9????????           |                     
            //   6a64                 | push                0x64
            //   ff15????????         |                     
            //   3975e8               | cmp                 dword ptr [ebp - 0x18], esi
            //   7435                 | je                  0x37

        $sequence_1 = { e8???????? 8d8560f9ffff 50 e8???????? 83c410 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   8d8560f9ffff         | lea                 eax, [ebp - 0x6a0]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10

        $sequence_2 = { 3bf3 bf???????? 7512 8b7508 68???????? }
            // n = 5, score = 100
            //   3bf3                 | cmp                 esi, ebx
            //   bf????????           |                     
            //   7512                 | jne                 0x14
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   68????????           |                     

        $sequence_3 = { 8d85bcd8ffff 50 e8???????? 59 8d8dbcd8ffff 83e903 803c0829 }
            // n = 7, score = 100
            //   8d85bcd8ffff         | lea                 eax, [ebp - 0x2744]
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8d8dbcd8ffff         | lea                 ecx, [ebp - 0x2744]
            //   83e903               | sub                 ecx, 3
            //   803c0829             | cmp                 byte ptr [eax + ecx], 0x29

        $sequence_4 = { 6a02 e9???????? 8b459c bb001c0000 8945e8 53 8d85bcd8ffff }
            // n = 7, score = 100
            //   6a02                 | push                2
            //   e9????????           |                     
            //   8b459c               | mov                 eax, dword ptr [ebp - 0x64]
            //   bb001c0000           | mov                 ebx, 0x1c00
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   53                   | push                ebx
            //   8d85bcd8ffff         | lea                 eax, [ebp - 0x2744]

        $sequence_5 = { 83c40c 85c0 0f844bfbffff ff35???????? }
            // n = 4, score = 100
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   0f844bfbffff         | je                  0xfffffb51
            //   ff35????????         |                     

        $sequence_6 = { ffb57cfeffff 50 8d850cffffff 68???????? 50 ff15???????? 83c424 }
            // n = 7, score = 100
            //   ffb57cfeffff         | push                dword ptr [ebp - 0x184]
            //   50                   | push                eax
            //   8d850cffffff         | lea                 eax, [ebp - 0xf4]
            //   68????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c424               | add                 esp, 0x24

        $sequence_7 = { ff15???????? 56 56 56 6a05 e9???????? }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   56                   | push                esi
            //   56                   | push                esi
            //   56                   | push                esi
            //   6a05                 | push                5
            //   e9????????           |                     

        $sequence_8 = { 50 e8???????? 83c430 8d459c 50 8d8518ffffff }
            // n = 6, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c430               | add                 esp, 0x30
            //   8d459c               | lea                 eax, [ebp - 0x64]
            //   50                   | push                eax
            //   8d8518ffffff         | lea                 eax, [ebp - 0xe8]

        $sequence_9 = { ff35???????? ff15???????? ff35???????? ff15???????? 8d85f0fdffff bb00010000 50 }
            // n = 7, score = 100
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   8d85f0fdffff         | lea                 eax, [ebp - 0x210]
            //   bb00010000           | mov                 ebx, 0x100
            //   50                   | push                eax

    condition:
        7 of them and filesize < 57344
}