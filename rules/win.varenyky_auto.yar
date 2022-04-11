rule win_varenyky_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.varenyky."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.varenyky"
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
        $sequence_0 = { 66837c241409 7505 beffff0100 8b3d???????? 8d542410 }
            // n = 5, score = 100
            //   66837c241409         | cmp                 word ptr [esp + 0x14], 9
            //   7505                 | jne                 7
            //   beffff0100           | mov                 esi, 0x1ffff
            //   8b3d????????         |                     
            //   8d542410             | lea                 edx, dword ptr [esp + 0x10]

        $sequence_1 = { 59 8b7508 8d34f590f14000 391e }
            // n = 4, score = 100
            //   59                   | pop                 ecx
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   8d34f590f14000       | lea                 esi, dword ptr [esi*8 + 0x40f190]
            //   391e                 | cmp                 dword ptr [esi], ebx

        $sequence_2 = { 68???????? 52 e8???????? 83c40c 6a40 8d442428 }
            // n = 6, score = 100
            //   68????????           |                     
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a40                 | push                0x40
            //   8d442428             | lea                 eax, dword ptr [esp + 0x28]

        $sequence_3 = { 00b859400023 d18a0688078a 46 018847018a46 }
            // n = 4, score = 100
            //   00b859400023         | add                 byte ptr [eax + 0x23004059], bh
            //   d18a0688078a         | ror                 dword ptr [edx - 0x75f877fa], 1
            //   46                   | inc                 esi
            //   018847018a46         | add                 dword ptr [eax + 0x468a0147], ecx

        $sequence_4 = { 89842438040000 53 33db 381d???????? 0f85f7010000 }
            // n = 5, score = 100
            //   89842438040000       | mov                 dword ptr [esp + 0x438], eax
            //   53                   | push                ebx
            //   33db                 | xor                 ebx, ebx
            //   381d????????         |                     
            //   0f85f7010000         | jne                 0x1fd

        $sequence_5 = { 83e00f 33f6 eb04 33f6 33c0 0fbe84c150c24000 6a07 }
            // n = 7, score = 100
            //   83e00f               | and                 eax, 0xf
            //   33f6                 | xor                 esi, esi
            //   eb04                 | jmp                 6
            //   33f6                 | xor                 esi, esi
            //   33c0                 | xor                 eax, eax
            //   0fbe84c150c24000     | movsx               eax, byte ptr [ecx + eax*8 + 0x40c250]
            //   6a07                 | push                7

        $sequence_6 = { 40 50 894c2424 894c2428 e8???????? 85c0 0f8528020000 }
            // n = 7, score = 100
            //   40                   | inc                 eax
            //   50                   | push                eax
            //   894c2424             | mov                 dword ptr [esp + 0x24], ecx
            //   894c2428             | mov                 dword ptr [esp + 0x28], ecx
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f8528020000         | jne                 0x22e

        $sequence_7 = { e8???????? 83c414 8b45fc ff34c5bcf24000 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   ff34c5bcf24000       | push                dword ptr [eax*8 + 0x40f2bc]

        $sequence_8 = { 84c0 7428 0fb63e 0fb6c0 eb12 8b45e0 8a8074fa4000 }
            // n = 7, score = 100
            //   84c0                 | test                al, al
            //   7428                 | je                  0x2a
            //   0fb63e               | movzx               edi, byte ptr [esi]
            //   0fb6c0               | movzx               eax, al
            //   eb12                 | jmp                 0x14
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   8a8074fa4000         | mov                 al, byte ptr [eax + 0x40fa74]

        $sequence_9 = { 896c2414 beffff0000 895c2418 8944241c 89442420 89442424 89442428 }
            // n = 7, score = 100
            //   896c2414             | mov                 dword ptr [esp + 0x14], ebp
            //   beffff0000           | mov                 esi, 0xffff
            //   895c2418             | mov                 dword ptr [esp + 0x18], ebx
            //   8944241c             | mov                 dword ptr [esp + 0x1c], eax
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   89442424             | mov                 dword ptr [esp + 0x24], eax
            //   89442428             | mov                 dword ptr [esp + 0x28], eax

    condition:
        7 of them and filesize < 24846336
}