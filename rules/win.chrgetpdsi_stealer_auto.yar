rule win_chrgetpdsi_stealer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.chrgetpdsi_stealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chrgetpdsi_stealer"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
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
        $sequence_0 = { 4889ca 83e11f 4883f90c 0f8743030000 4c8d41fe 4983f804 0f869a010000 }
            // n = 7, score = 500
            //   4889ca               | dec                 eax
            //   83e11f               | mov                 dword ptr [esp + 0x50], ecx
            //   4883f90c             | dec                 eax
            //   0f8743030000         | lea                 eax, [0x2b368a]
            //   4c8d41fe             | mov                 ebx, 0x13
            //   4983f804             | dec                 eax
            //   0f869a010000         | mov                 dword ptr [esp + 0x58], ebx

        $sequence_1 = { eb11 488d7818 488b8c24580b0000 e8???????? 48c7400810000000 488d0de6c51a00 488908 }
            // n = 7, score = 500
            //   eb11                 | mov                 ebp, dword ptr [esp + 0x120]
            //   488d7818             | dec                 eax
            //   488b8c24580b0000     | add                 esp, 0x128
            //   e8????????           |                     
            //   48c7400810000000     | ret                 
            //   488d0de6c51a00       | dec                 eax
            //   488908               | lea                 edi, [esp + 0xd0]

        $sequence_2 = { e8???????? 488d059bb42d00 bb03000000 0f1f440000 e8???????? 488b442450 e8???????? }
            // n = 7, score = 500
            //   e8????????           |                     
            //   488d059bb42d00       | dec                 eax
            //   bb03000000           | lea                 eax, [0x315f6a]
            //   0f1f440000           | mov                 ebx, 1
            //   e8????????           |                     
            //   488b442450           | nop                 
            //   e8????????           |                     

        $sequence_3 = { be01000000 4c8d1557bd2300 41bb02000000 e8???????? 488b6c2458 4883c460 c3 }
            // n = 7, score = 500
            //   be01000000           | lea                 ebx, [esp + 0x4a0]
            //   4c8d1557bd2300       | dec                 eax
            //   41bb02000000         | lea                 ecx, [0x171cba]
            //   e8????????           |                     
            //   488b6c2458           | cmp                 dword ptr [eax], 0x656e6f6e
            //   4883c460             | jne                 0x2490
            //   c3                   | xor                 eax, eax

        $sequence_4 = { 4983fd2e 0f82e3060000 4c8d69d2 49f7dd 49c1fd3f 4183e52e 4901c5 }
            // n = 7, score = 500
            //   4983fd2e             | mov                 ecx, dword ptr [esp + 0x78]
            //   0f82e3060000         | dec                 ebp
            //   4c8d69d2             | mov                 dword ptr [eax + edx*8 + 0x10], ecx
            //   49f7dd               | dec                 ecx
            //   49c1fd3f             | lea                 edi, [eax + edx*8]
            //   4183e52e             | dec                 eax
            //   4901c5               | lea                 edx, [eax + eax*2]

        $sequence_5 = { e8???????? 8400 488b9424d8000000 488b7270 440f11bc2498000000 440f11bc24a8000000 488d3db2020000 }
            // n = 7, score = 500
            //   e8????????           |                     
            //   8400                 | lea                 ebp, [esp + 0x20]
            //   488b9424d8000000     | dec                 ebp
            //   488b7270             | cmp                 dword ptr [esp], ebp
            //   440f11bc2498000000     | jne    0x13f2
            //   440f11bc24a8000000     | ret    
            //   488d3db2020000       | movdqu              xmm1, xmmword ptr [eax + ecx - 0x20]

        $sequence_6 = { 7476 440fb74b52 4d89c2 4b8d3c01 488d7ff8 8403 48833f00 }
            // n = 7, score = 500
            //   7476                 | dec                 eax
            //   440fb74b52           | lea                 eax, [0x2da955]
            //   4d89c2               | dec                 eax
            //   4b8d3c01             | mov                 edx, dword ptr [eax + ebx*8]
            //   488d7ff8             | dec                 eax
            //   8403                 | add                 ebx, 0xa
            //   48833f00             | dec                 eax

        $sequence_7 = { c3 488d05b0351c00 488d1dd9212400 e8???????? 90 4889442408 e8???????? }
            // n = 7, score = 500
            //   c3                   | mov                 ecx, dword ptr [esp + 0xa00]
            //   488d05b0351c00       | jne                 0x8db
            //   488d1dd9212400       | dec                 eax
            //   e8????????           |                     
            //   90                   | mov                 ecx, dword ptr [esp + 0xc28]
            //   4889442408           | dec                 eax
            //   e8????????           |                     

        $sequence_8 = { e8???????? 488d3d09643e00 488b442438 0f1f4000 e8???????? e8???????? 4889442430 }
            // n = 7, score = 500
            //   e8????????           |                     
            //   488d3d09643e00       | dec                 eax
            //   488b442438           | mov                 dword ptr [esp + 0x90], ecx
            //   0f1f4000             | ret                 
            //   e8????????           |                     
            //   e8????????           |                     
            //   4889442430           | inc                 ecx

        $sequence_9 = { 833d????????00 7509 488905???????? eb0c 488d3dbeda3b00 e8???????? 488b0d???????? }
            // n = 7, score = 500
            //   833d????????00       |                     
            //   7509                 | jbe                 0x785
            //   488905????????       |                     
            //   eb0c                 | dec                 ebp
            //   488d3dbeda3b00       | mov                 esi, dword ptr [esi]
            //   e8????????           |                     
            //   488b0d????????       |                     

    condition:
        7 of them and filesize < 10027008
}