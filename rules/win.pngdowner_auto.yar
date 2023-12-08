rule win_pngdowner_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.pngdowner."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pngdowner"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
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
        $sequence_0 = { 8b4508 c705????????01000000 50 a3???????? e8???????? 8db6bcdc4000 bf???????? }
            // n = 7, score = 200
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   c705????????01000000     |     
            //   50                   | push                eax
            //   a3????????           |                     
            //   e8????????           |                     
            //   8db6bcdc4000         | lea                 esi, [esi + 0x40dcbc]
            //   bf????????           |                     

        $sequence_1 = { ff15???????? 85c0 a3???????? 741b 6a00 6a00 }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   a3????????           |                     
            //   741b                 | je                  0x1d
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_2 = { 7552 833c8580e0400000 53 57 }
            // n = 4, score = 200
            //   7552                 | jne                 0x54
            //   833c8580e0400000     | cmp                 dword ptr [eax*4 + 0x40e080], 0
            //   53                   | push                ebx
            //   57                   | push                edi

        $sequence_3 = { c74050c0b54000 c7401401000000 c3 56 57 ff15???????? }
            // n = 6, score = 200
            //   c74050c0b54000       | mov                 dword ptr [eax + 0x50], 0x40b5c0
            //   c7401401000000       | mov                 dword ptr [eax + 0x14], 1
            //   c3                   | ret                 
            //   56                   | push                esi
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_4 = { c1ff05 83e11f 8b3cbd40e64000 8d0cc9 8d3c8f eb05 bf???????? }
            // n = 7, score = 200
            //   c1ff05               | sar                 edi, 5
            //   83e11f               | and                 ecx, 0x1f
            //   8b3cbd40e64000       | mov                 edi, dword ptr [edi*4 + 0x40e640]
            //   8d0cc9               | lea                 ecx, [ecx + ecx*8]
            //   8d3c8f               | lea                 edi, [edi + ecx*4]
            //   eb05                 | jmp                 7
            //   bf????????           |                     

        $sequence_5 = { 83c8ff 5b 81c420000100 c3 8b3d???????? 8d4c2420 }
            // n = 6, score = 200
            //   83c8ff               | or                  eax, 0xffffffff
            //   5b                   | pop                 ebx
            //   81c420000100         | add                 esp, 0x10020
            //   c3                   | ret                 
            //   8b3d????????         |                     
            //   8d4c2420             | lea                 ecx, [esp + 0x20]

        $sequence_6 = { ff74240c e8???????? 83c40c c3 e8???????? 8b4c2404 894814 }
            // n = 7, score = 200
            //   ff74240c             | push                dword ptr [esp + 0xc]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   c3                   | ret                 
            //   e8????????           |                     
            //   8b4c2404             | mov                 ecx, dword ptr [esp + 4]
            //   894814               | mov                 dword ptr [eax + 0x14], ecx

        $sequence_7 = { c3 33c0 5e c3 8b442404 c74050c0b54000 }
            // n = 6, score = 200
            //   c3                   | ret                 
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   8b442404             | mov                 eax, dword ptr [esp + 4]
            //   c74050c0b54000       | mov                 dword ptr [eax + 0x50], 0x40b5c0

        $sequence_8 = { 8b1d???????? b900400000 33c0 8d7c2420 8d542420 }
            // n = 5, score = 200
            //   8b1d????????         |                     
            //   b900400000           | mov                 ecx, 0x4000
            //   33c0                 | xor                 eax, eax
            //   8d7c2420             | lea                 edi, [esp + 0x20]
            //   8d542420             | lea                 edx, [esp + 0x20]

        $sequence_9 = { ff742404 e8???????? 59 c3 56 8bf1 6a1b }
            // n = 7, score = 200
            //   ff742404             | push                dword ptr [esp + 4]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   6a1b                 | push                0x1b

    condition:
        7 of them and filesize < 131072
}