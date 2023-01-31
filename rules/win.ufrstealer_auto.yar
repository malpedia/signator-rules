rule win_ufrstealer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.ufrstealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ufrstealer"
        malpedia_rule_date = "20230124"
        malpedia_hash = "2ee0eebba83dce3d019a90519f2f972c0fcf9686"
        malpedia_version = "20230125"
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
        $sequence_0 = { 8975ec 3bf2 7284 5a eb05 e9???????? 60 }
            // n = 7, score = 200
            //   8975ec               | mov                 dword ptr [ebp - 0x14], esi
            //   3bf2                 | cmp                 esi, edx
            //   7284                 | jb                  0xffffff86
            //   5a                   | pop                 edx
            //   eb05                 | jmp                 7
            //   e9????????           |                     
            //   60                   | pushal              

        $sequence_1 = { c705????????00000000 c705????????28000000 6a00 68???????? 6a04 68???????? ff35???????? }
            // n = 7, score = 200
            //   c705????????00000000     |     
            //   c705????????28000000     |     
            //   6a00                 | push                0
            //   68????????           |                     
            //   6a04                 | push                4
            //   68????????           |                     
            //   ff35????????         |                     

        $sequence_2 = { 0bc0 0f85bc010000 68???????? 8d8500f8ffff 50 ff15???????? 0bc0 }
            // n = 7, score = 200
            //   0bc0                 | or                  eax, eax
            //   0f85bc010000         | jne                 0x1c2
            //   68????????           |                     
            //   8d8500f8ffff         | lea                 eax, [ebp - 0x800]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   0bc0                 | or                  eax, eax

        $sequence_3 = { ff15???????? 50 ff75f4 68???????? e8???????? 85c0 0f843b020000 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   68????????           |                     
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f843b020000         | je                  0x241

        $sequence_4 = { eb62 803d????????00 7411 6a00 68???????? ff15???????? 85c0 }
            // n = 7, score = 200
            //   eb62                 | jmp                 0x64
            //   803d????????00       |                     
            //   7411                 | je                  0x13
            //   6a00                 | push                0
            //   68????????           |                     
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_5 = { 0f84d2dbffff 8d45ec 50 6801000001 6810660000 ff75f0 ff15???????? }
            // n = 7, score = 200
            //   0f84d2dbffff         | je                  0xffffdbd8
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   50                   | push                eax
            //   6801000001           | push                0x1000001
            //   6810660000           | push                0x6610
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   ff15????????         |                     

        $sequence_6 = { 8b4030 50 68???????? ff15???????? 68???????? ff15???????? }
            // n = 6, score = 200
            //   8b4030               | mov                 eax, dword ptr [eax + 0x30]
            //   50                   | push                eax
            //   68????????           |                     
            //   ff15????????         |                     
            //   68????????           |                     
            //   ff15????????         |                     

        $sequence_7 = { ff75e4 68???????? e8???????? 85c0 0f847e020000 2b45dc }
            // n = 6, score = 200
            //   ff75e4               | push                dword ptr [ebp - 0x1c]
            //   68????????           |                     
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f847e020000         | je                  0x284
            //   2b45dc               | sub                 eax, dword ptr [ebp - 0x24]

        $sequence_8 = { 59 46 49 0f8580feffff ff75f4 ff15???????? 648f0500000000 }
            // n = 7, score = 200
            //   59                   | pop                 ecx
            //   46                   | inc                 esi
            //   49                   | dec                 ecx
            //   0f8580feffff         | jne                 0xfffffe86
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   ff15????????         |                     
            //   648f0500000000       | pop                 dword ptr fs:[0]

        $sequence_9 = { ff75e4 68???????? e8???????? 85c0 0f848c010000 2b45dc 83c001 }
            // n = 7, score = 200
            //   ff75e4               | push                dword ptr [ebp - 0x1c]
            //   68????????           |                     
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f848c010000         | je                  0x192
            //   2b45dc               | sub                 eax, dword ptr [ebp - 0x24]
            //   83c001               | add                 eax, 1

    condition:
        7 of them and filesize < 770048
}