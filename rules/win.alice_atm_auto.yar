rule win_alice_atm_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.alice_atm."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.alice_atm"
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
        $sequence_0 = { 68???????? 57 ff7514 e8???????? ff7609 e8???????? }
            // n = 6, score = 100
            //   68????????           |                     
            //   57                   | push                edi
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   e8????????           |                     
            //   ff7609               | push                dword ptr [esi + 9]
            //   e8????????           |                     

        $sequence_1 = { 0bff 7440 57 6a40 e8???????? 0bc0 7434 }
            // n = 7, score = 100
            //   0bff                 | or                  edi, edi
            //   7440                 | je                  0x42
            //   57                   | push                edi
            //   6a40                 | push                0x40
            //   e8????????           |                     
            //   0bc0                 | or                  eax, eax
            //   7434                 | je                  0x36

        $sequence_2 = { 0fb77e02 8bdf 6bff10 0bff 7440 57 6a40 }
            // n = 7, score = 100
            //   0fb77e02             | movzx               edi, word ptr [esi + 2]
            //   8bdf                 | mov                 ebx, edi
            //   6bff10               | imul                edi, edi, 0x10
            //   0bff                 | or                  edi, edi
            //   7440                 | je                  0x42
            //   57                   | push                edi
            //   6a40                 | push                0x40

        $sequence_3 = { 53 ff13 6a50 68???????? 53 ff13 }
            // n = 6, score = 100
            //   53                   | push                ebx
            //   ff13                 | call                dword ptr [ebx]
            //   6a50                 | push                0x50
            //   68????????           |                     
            //   53                   | push                ebx
            //   ff13                 | call                dword ptr [ebx]

        $sequence_4 = { e8???????? 8d5da8 68ec030000 ff7508 e8???????? }
            // n = 5, score = 100
            //   e8????????           |                     
            //   8d5da8               | lea                 ebx, dword ptr [ebp - 0x58]
            //   68ec030000           | push                0x3ec
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     

        $sequence_5 = { 0f8407010000 817e0c20202000 0f8480000000 ff36 68???????? 8d45f8 }
            // n = 6, score = 100
            //   0f8407010000         | je                  0x10d
            //   817e0c20202000       | cmp                 dword ptr [esi + 0xc], 0x202020
            //   0f8480000000         | je                  0x86
            //   ff36                 | push                dword ptr [esi]
            //   68????????           |                     
            //   8d45f8               | lea                 eax, dword ptr [ebp - 8]

        $sequence_6 = { 68???????? ff7514 e8???????? 8b45fc }
            // n = 4, score = 100
            //   68????????           |                     
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_7 = { c74310f7164000 c743142a174000 c7431842174000 c7431c5a174000 }
            // n = 4, score = 100
            //   c74310f7164000       | mov                 dword ptr [ebx + 0x10], 0x4016f7
            //   c743142a174000       | mov                 dword ptr [ebx + 0x14], 0x40172a
            //   c7431842174000       | mov                 dword ptr [ebx + 0x18], 0x401742
            //   c7431c5a174000       | mov                 dword ptr [ebx + 0x1c], 0x40175a

        $sequence_8 = { e8???????? 53 e8???????? 8d5da8 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   53                   | push                ebx
            //   e8????????           |                     
            //   8d5da8               | lea                 ebx, dword ptr [ebp - 0x58]

        $sequence_9 = { 68???????? 57 ff7514 e8???????? ff7609 }
            // n = 5, score = 100
            //   68????????           |                     
            //   57                   | push                edi
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   e8????????           |                     
            //   ff7609               | push                dword ptr [esi + 9]

    condition:
        7 of them and filesize < 49152
}