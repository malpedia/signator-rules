rule win_glitch_pos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.glitch_pos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.glitch_pos"
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
        $sequence_0 = { e8???????? 8d4dd0 e8???????? e8???????? 8d8520ffffff 50 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8d4dd0               | lea                 ecx, dword ptr [ebp - 0x30]
            //   e8????????           |                     
            //   e8????????           |                     
            //   8d8520ffffff         | lea                 eax, dword ptr [ebp - 0xe0]
            //   50                   | push                eax

        $sequence_1 = { 898560ffffff 83bd60ffffff00 7d20 6a40 68???????? ffb564ffffff }
            // n = 6, score = 100
            //   898560ffffff         | mov                 dword ptr [ebp - 0xa0], eax
            //   83bd60ffffff00       | cmp                 dword ptr [ebp - 0xa0], 0
            //   7d20                 | jge                 0x22
            //   6a40                 | push                0x40
            //   68????????           |                     
            //   ffb564ffffff         | push                dword ptr [ebp - 0x9c]

        $sequence_2 = { 83a554feffff00 d985fcfeffff d99d1cffffff c78514ffffff04000000 }
            // n = 4, score = 100
            //   83a554feffff00       | and                 dword ptr [ebp - 0x1ac], 0
            //   d985fcfeffff         | fld                 dword ptr [ebp - 0x104]
            //   d99d1cffffff         | fstp                dword ptr [ebp - 0xe4]
            //   c78514ffffff04000000     | mov    dword ptr [ebp - 0xec], 4

        $sequence_3 = { 50 8b45c8 8b00 ff75c8 ff5050 dbe2 8945c4 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8b45c8               | mov                 eax, dword ptr [ebp - 0x38]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   ff75c8               | push                dword ptr [ebp - 0x38]
            //   ff5050               | call                dword ptr [eax + 0x50]
            //   dbe2                 | fnclex              
            //   8945c4               | mov                 dword ptr [ebp - 0x3c], eax

        $sequence_4 = { ff90ec010000 dbe2 89850cffffff 83bd0cffffff00 7d23 68ec010000 }
            // n = 6, score = 100
            //   ff90ec010000         | call                dword ptr [eax + 0x1ec]
            //   dbe2                 | fnclex              
            //   89850cffffff         | mov                 dword ptr [ebp - 0xf4], eax
            //   83bd0cffffff00       | cmp                 dword ptr [ebp - 0xf4], 0
            //   7d23                 | jge                 0x25
            //   68ec010000           | push                0x1ec

        $sequence_5 = { eb07 83a5fcfdffff00 8d45c4 50 8d45cc 50 6a02 }
            // n = 7, score = 100
            //   eb07                 | jmp                 9
            //   83a5fcfdffff00       | and                 dword ptr [ebp - 0x204], 0
            //   8d45c4               | lea                 eax, dword ptr [ebp - 0x3c]
            //   50                   | push                eax
            //   8d45cc               | lea                 eax, dword ptr [ebp - 0x34]
            //   50                   | push                eax
            //   6a02                 | push                2

        $sequence_6 = { c745fc20000000 c78534ffffff01000000 c7852cffffff02000000 8d459c }
            // n = 4, score = 100
            //   c745fc20000000       | mov                 dword ptr [ebp - 4], 0x20
            //   c78534ffffff01000000     | mov    dword ptr [ebp - 0xcc], 1
            //   c7852cffffff02000000     | mov    dword ptr [ebp - 0xd4], 2
            //   8d459c               | lea                 eax, dword ptr [ebp - 0x64]

        $sequence_7 = { 8d45cc 50 8b8520ffffff 8b00 ffb520ffffff ff5050 }
            // n = 6, score = 100
            //   8d45cc               | lea                 eax, dword ptr [ebp - 0x34]
            //   50                   | push                eax
            //   8b8520ffffff         | mov                 eax, dword ptr [ebp - 0xe0]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   ffb520ffffff         | push                dword ptr [ebp - 0xe0]
            //   ff5050               | call                dword ptr [eax + 0x50]

        $sequence_8 = { 7d23 68c0010000 68???????? ffb5f0feffff ffb5ecfeffff }
            // n = 5, score = 100
            //   7d23                 | jge                 0x25
            //   68c0010000           | push                0x1c0
            //   68????????           |                     
            //   ffb5f0feffff         | push                dword ptr [ebp - 0x110]
            //   ffb5ecfeffff         | push                dword ptr [ebp - 0x114]

        $sequence_9 = { 83a57cffffff00 c78574ffffff02000000 8d4594 50 8d4584 50 8d8574ffffff }
            // n = 7, score = 100
            //   83a57cffffff00       | and                 dword ptr [ebp - 0x84], 0
            //   c78574ffffff02000000     | mov    dword ptr [ebp - 0x8c], 2
            //   8d4594               | lea                 eax, dword ptr [ebp - 0x6c]
            //   50                   | push                eax
            //   8d4584               | lea                 eax, dword ptr [ebp - 0x7c]
            //   50                   | push                eax
            //   8d8574ffffff         | lea                 eax, dword ptr [ebp - 0x8c]

    condition:
        7 of them and filesize < 1024000
}