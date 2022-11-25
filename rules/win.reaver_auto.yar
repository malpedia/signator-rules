rule win_reaver_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.reaver."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.reaver"
        malpedia_rule_date = "20221118"
        malpedia_hash = "e0702e2e6d1d00da65c8a29a4ebacd0a4c59e1af"
        malpedia_version = "20221125"
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
        $sequence_0 = { ff15???????? 85c0 7453 8d45f4 50 ff7508 6a00 }
            // n = 7, score = 900
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7453                 | je                  0x55
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]
            //   6a00                 | push                0

        $sequence_1 = { 740d ff15???????? 3d14050000 7504 33c0 }
            // n = 5, score = 900
            //   740d                 | je                  0xf
            //   ff15????????         |                     
            //   3d14050000           | cmp                 eax, 0x514
            //   7504                 | jne                 6
            //   33c0                 | xor                 eax, eax

        $sequence_2 = { ff15???????? 85c0 7453 8d45f4 50 ff7508 }
            // n = 6, score = 900
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7453                 | je                  0x55
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_3 = { 85c0 7440 8b45f4 6a00 8945e8 8b45f8 8945ec }
            // n = 7, score = 900
            //   85c0                 | test                eax, eax
            //   7440                 | je                  0x42
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   6a00                 | push                0
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax

        $sequence_4 = { 68ff010f00 ff15???????? 50 ff15???????? 85c0 7453 }
            // n = 6, score = 900
            //   68ff010f00           | push                0xf01ff
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7453                 | je                  0x55

        $sequence_5 = { 7440 8b45f4 6a00 8945e8 8b45f8 }
            // n = 5, score = 900
            //   7440                 | je                  0x42
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   6a00                 | push                0
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

        $sequence_6 = { ff15???????? 85c0 740d ff15???????? 3d14050000 }
            // n = 5, score = 900
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   740d                 | je                  0xf
            //   ff15????????         |                     
            //   3d14050000           | cmp                 eax, 0x514

        $sequence_7 = { 55 8bec 83ec1c 8d45fc 50 68ff010f00 ff15???????? }
            // n = 7, score = 900
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec1c               | sub                 esp, 0x1c
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   68ff010f00           | push                0xf01ff
            //   ff15????????         |                     

        $sequence_8 = { 85c0 7440 8b45f4 6a00 }
            // n = 4, score = 900
            //   85c0                 | test                eax, eax
            //   7440                 | je                  0x42
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   6a00                 | push                0

        $sequence_9 = { ff7508 6a00 ff15???????? 85c0 7440 }
            // n = 5, score = 900
            //   ff7508               | push                dword ptr [ebp + 8]
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7440                 | je                  0x42

    condition:
        7 of them and filesize < 106496
}