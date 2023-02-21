rule win_fudmodule_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.fudmodule."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fudmodule"
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
        $sequence_0 = { 488d3cb0 ff15???????? 488d542448 488bc8 488d442460 41b904000000 4c8bc7 }
            // n = 7, score = 100
            //   488d3cb0             | add                 ecx, 2
            //   ff15????????         |                     
            //   488d542448           | jbe                 0x29
            //   488bc8               | add                 eax, 0xfffc0860
            //   488d442460           | cmp                 eax, 0x270e
            //   41b904000000         | ja                  0x36
            //   4c8bc7               | dec                 eax

        $sequence_1 = { 488b8df0010000 4833cc e8???????? 4c8d9c2400030000 498b5b28 498b7330 }
            // n = 6, score = 100
            //   488b8df0010000       | call                dword ptr [ebx + 0xdd0]
            //   4833cc               | dec                 eax
            //   e8????????           |                     
            //   4c8d9c2400030000     | mov                 ecx, dword ptr [ebp - 0x70]
            //   498b5b28             | dec                 esp
            //   498b7330             | mov                 eax, dword ptr [ebp - 0x70]

        $sequence_2 = { 48c781f0090000f6010000 8bc2 c3 3d5a290000 0f846cffffff 3d39380000 }
            // n = 6, score = 100
            //   48c781f0090000f6010000     | inc    ecx
            //   8bc2                 | mov                 eax, 6
            //   c3                   | dec                 eax
            //   3d5a290000           | lea                 edx, [0x98d4]
            //   0f846cffffff         | dec                 eax
            //   3d39380000           | cmp                 dword ptr [eax - 0x10], edx

        $sequence_3 = { 488b8bc0090000 8b440a20 4803440a18 4c3bc8 }
            // n = 4, score = 100
            //   488b8bc0090000       | dec                 eax
            //   8b440a20             | add                 edx, 2
            //   4803440a18           | imul                cl
            //   4c3bc8               | xor                 byte ptr [edx - 2], al

        $sequence_4 = { c3 3d5a290000 0f846cffffff 3d39380000 e9???????? 3dbb470000 7f21 }
            // n = 7, score = 100
            //   c3                   | dec                 esp
            //   3d5a290000           | mov                 eax, dword ptr [ebx + 0x9c0]
            //   0f846cffffff         | dec                 eax
            //   3d39380000           | or                  ecx, 0xffffffff
            //   e9????????           |                     
            //   3dbb470000           | cmp                 dl, byte ptr [ecx + 2]
            //   7f21                 | je                  0xe11

        $sequence_5 = { 41b800100000 488bd8 488d45ef 488bd6 b902000000 41c78424300a000000000000 }
            // n = 6, score = 100
            //   41b800100000         | dec                 ecx
            //   488bd8               | mov                 eax, dword ptr [esp + esi*8]
            //   488d45ef             | movsx               ecx, byte ptr [eax + ebx + 8]
            //   488bd6               | dec                 esp
            //   b902000000           | lea                 esp, [0xe156]
            //   41c78424300a000000000000     | jmp    0xbf7

        $sequence_6 = { 3b0d???????? 7369 4863d9 488d2dfbbc0000 488bfb 83e31f }
            // n = 6, score = 100
            //   3b0d????????         |                     
            //   7369                 | dec                 eax
            //   4863d9               | and                 dword ptr [esp + 0x20], 0
            //   488d2dfbbc0000       | dec                 eax
            //   488bfb               | lea                 eax, [0xdd35]
            //   83e31f               | mov                 byte ptr [esp + 0x60], 0xd

        $sequence_7 = { 4889442458 488b8424c0000000 4889442460 410fb78220010000 3db11d0000 741e 3df0230000 }
            // n = 7, score = 100
            //   4889442458           | mov                 edx, ebp
            //   488b8424c0000000     | inc                 ecx
            //   4889442460           | lea                 edi, [esp - 0x19]
            //   410fb78220010000     | dec                 esp
            //   3db11d0000           | lea                 esi, [0xd820]
            //   741e                 | and                 ebx, 0x1f
            //   3df0230000           | dec                 eax

        $sequence_8 = { ff15???????? 488d0d7f7c0000 ff15???????? 833d????????00 750a b901000000 e8???????? }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   488d0d7f7c0000       | jle                 0x29
            //   ff15????????         |                     
            //   833d????????00       |                     
            //   750a                 | mov                 eax, 0x18
            //   b901000000           | mov                 ecx, eax
            //   e8????????           |                     

        $sequence_9 = { 85c0 0f44d9 488b4c2430 ff15???????? 8bc3 488b8d00040000 4833cc }
            // n = 7, score = 100
            //   85c0                 | je                  0x5c1
            //   0f44d9               | dec                 esp
            //   488b4c2430           | mov                 dword ptr [esp + 0xe0], ebp
            //   ff15????????         |                     
            //   8bc3                 | dec                 ebp
            //   488b8d00040000       | lea                 ebp, [ebx + 0x10]
            //   4833cc               | dec                 eax

    condition:
        7 of them and filesize < 223232
}