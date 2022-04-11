rule win_rgdoor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.rgdoor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rgdoor"
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
        $sequence_0 = { 488b742440 488bc3 488b5c2430 4883c420 5f c3 488d0d5d600200 }
            // n = 7, score = 100
            //   488b742440           | cmp                 eax, edx
            //   488bc3               | dec                 ecx
            //   488b5c2430           | cmp                 dword ptr [eax + 0x10], ebp
            //   4883c420             | je                  0x763
            //   5f                   | inc                 esp
            //   c3                   | lea                 eax, dword ptr [ebp + 2]
            //   488d0d5d600200       | dec                 eax

        $sequence_1 = { e8???????? 488d85e0000000 4889442448 488b85e0000000 48634804 488b8c0d28010000 4885c9 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488d85e0000000       | test                ecx, ecx
            //   4889442448           | jne                 0x17e0
            //   488b85e0000000       | dec                 eax
            //   48634804             | add                 esp, 0x28
            //   488b8c0d28010000     | ret                 
            //   4885c9               | inc                 eax

        $sequence_2 = { 488d3db8ff0100 482bfe 8a041f 8803 }
            // n = 4, score = 100
            //   488d3db8ff0100       | dec                 eax
            //   482bfe               | mov                 dword ptr [edx + ecx*8], eax
            //   8a041f               | dec                 eax
            //   8803                 | add                 esp, 0x28

        $sequence_3 = { 4c8d05054c0200 498904d0 44012d???????? 498b04d0 4805000b0000 483bc8 }
            // n = 6, score = 100
            //   4c8d05054c0200       | lea                 eax, dword ptr [0x22762]
            //   498904d0             | dec                 eax
            //   44012d????????       |                     
            //   498b04d0             | mov                 eax, dword ptr [eax + edi*8]
            //   4805000b0000         | dec                 esp
            //   483bc8               | lea                 esp, dword ptr [0x1fc7b]

        $sequence_4 = { 488b4350 ff00 488b4338 48ff08 33c0 83faff 0f45c2 }
            // n = 7, score = 100
            //   488b4350             | dec                 eax
            //   ff00                 | mov                 dword ptr [edi + 0x10], ebp
            //   488b4338             | mov                 byte ptr [edi], 0
            //   48ff08               | dec                 eax
            //   33c0                 | cmp                 dword ptr [ebx + 0x18], 0x10
            //   83faff               | jae                 0x3ec
            //   0f45c2               | dec                 esp

        $sequence_5 = { 488d05064e0200 48898424a8000000 488d15e78f0200 488d8c24a8000000 e8???????? 90 }
            // n = 6, score = 100
            //   488d05064e0200       | je                  0xb73
            //   48898424a8000000     | dec                 esp
            //   488d15e78f0200       | lea                 edx, dword ptr [0xfffe7e89]
            //   488d8c24a8000000     | test                eax, eax
            //   e8????????           |                     
            //   90                   | jne                 0xafb

        $sequence_6 = { 83e21f 486bc258 490304c9 488d0d279f0200 eb0a 488d0d1e9f0200 488bc1 }
            // n = 7, score = 100
            //   83e21f               | dec                 eax
            //   486bc258             | arpl                cx, ax
            //   490304c9             | dec                 esp
            //   488d0d279f0200       | lea                 esi, dword ptr [0x1c5c6]
            //   eb0a                 | dec                 eax
            //   488d0d1e9f0200       | mov                 edi, eax
            //   488bc1               | and                 eax, 0x1f

        $sequence_7 = { 8d4101 4533c0 3bc2 7411 438b848604290200 }
            // n = 5, score = 100
            //   8d4101               | inc                 ecx
            //   4533c0               | or                  byte ptr [edi + eax + 8], 0x10
            //   3bc2                 | dec                 eax
            //   7411                 | mov                 ecx, dword ptr [esp + 0x40]
            //   438b848604290200     | dec                 eax

        $sequence_8 = { c3 48897c2458 4885c9 7504 33ff eb11 488b4358 }
            // n = 7, score = 100
            //   c3                   | dec                 eax
            //   48897c2458           | arpl                cx, ax
            //   4885c9               | dec                 esp
            //   7504                 | lea                 esi, dword ptr [0x1c5c6]
            //   33ff                 | dec                 eax
            //   eb11                 | mov                 edi, eax
            //   488b4358             | and                 eax, 0x1f

        $sequence_9 = { 0f8c67ffffff 48837dd010 7209 488b4db8 e8???????? 48c745d00f000000 4c8965c8 }
            // n = 7, score = 100
            //   0f8c67ffffff         | dec                 eax
            //   48837dd010           | mov                 eax, dword ptr [ecx + 0xb0]
            //   7209                 | dec                 eax
            //   488b4db8             | mov                 dword ptr [ecx + 0x100], ebx
            //   e8????????           |                     
            //   48c745d00f000000     | dec                 eax
            //   4c8965c8             | mov                 dword ptr [ecx + 0x110], eax

    condition:
        7 of them and filesize < 475136
}