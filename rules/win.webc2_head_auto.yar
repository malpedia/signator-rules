rule win_webc2_head_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.webc2_head."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_head"
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
        $sequence_0 = { be???????? 8dbc24c0000000 f3a5 a4 b910000000 }
            // n = 5, score = 100
            //   be????????           |                     
            //   8dbc24c0000000       | lea                 edi, dword ptr [esp + 0xc0]
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   a4                   | movsb               byte ptr es:[edi], byte ptr [esi]
            //   b910000000           | mov                 ecx, 0x10

        $sequence_1 = { 4a 894c2418 0f8550ffffff 8b6c2424 8b542414 8b4c242c }
            // n = 6, score = 100
            //   4a                   | dec                 edx
            //   894c2418             | mov                 dword ptr [esp + 0x18], ecx
            //   0f8550ffffff         | jne                 0xffffff56
            //   8b6c2424             | mov                 ebp, dword ptr [esp + 0x24]
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   8b4c242c             | mov                 ecx, dword ptr [esp + 0x2c]

        $sequence_2 = { 7d09 8a840440020000 eb02 b03d 0fbec0 c1e008 0bc1 }
            // n = 7, score = 100
            //   7d09                 | jge                 0xb
            //   8a840440020000       | mov                 al, byte ptr [esp + eax + 0x240]
            //   eb02                 | jmp                 4
            //   b03d                 | mov                 al, 0x3d
            //   0fbec0               | movsx               eax, al
            //   c1e008               | shl                 eax, 8
            //   0bc1                 | or                  eax, ecx

        $sequence_3 = { c642ff00 6a03 f2ae f7d1 49 }
            // n = 5, score = 100
            //   c642ff00             | mov                 byte ptr [edx - 1], 0
            //   6a03                 | push                3
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx

        $sequence_4 = { ff15???????? 85c0 5d 7512 ff15???????? 5f 5e }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   5d                   | pop                 ebp
            //   7512                 | jne                 0x14
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_5 = { f2ae f7d1 49 51 68???????? 50 50 }
            // n = 7, score = 100
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx
            //   51                   | push                ecx
            //   68????????           |                     
            //   50                   | push                eax
            //   50                   | push                eax

        $sequence_6 = { f3a4 8344241003 8dbc24c8030000 83c9ff }
            // n = 4, score = 100
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8344241003           | add                 dword ptr [esp + 0x10], 3
            //   8dbc24c8030000       | lea                 edi, dword ptr [esp + 0x3c8]
            //   83c9ff               | or                  ecx, 0xffffffff

        $sequence_7 = { 6a00 68bb010000 68???????? 53 ff15???????? }
            // n = 5, score = 100
            //   6a00                 | push                0
            //   68bb010000           | push                0x1bb
            //   68????????           |                     
            //   53                   | push                ebx
            //   ff15????????         |                     

        $sequence_8 = { be???????? 8dbc24b8010000 f3a5 a4 b910000000 be???????? }
            // n = 6, score = 100
            //   be????????           |                     
            //   8dbc24b8010000       | lea                 edi, dword ptr [esp + 0x1b8]
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   a4                   | movsb               byte ptr es:[edi], byte ptr [esi]
            //   b910000000           | mov                 ecx, 0x10
            //   be????????           |                     

        $sequence_9 = { 0890e1b94000 40 3bc7 76f5 41 }
            // n = 5, score = 100
            //   0890e1b94000         | or                  byte ptr [eax + 0x40b9e1], dl
            //   40                   | inc                 eax
            //   3bc7                 | cmp                 eax, edi
            //   76f5                 | jbe                 0xfffffff7
            //   41                   | inc                 ecx

    condition:
        7 of them and filesize < 106496
}