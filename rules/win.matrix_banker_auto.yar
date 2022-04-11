rule win_matrix_banker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.matrix_banker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.matrix_banker"
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
        $sequence_0 = { ff15???????? e8???????? 85c0 740a e8???????? }
            // n = 5, score = 900
            //   ff15????????         |                     
            //   e8????????           |                     
            //   85c0                 | lea                 edx, dword ptr [esi + 6]
            //   740a                 | mov                 dword ptr [esp + 0x18], edx
            //   e8????????           |                     

        $sequence_1 = { eb0a 8d48bf 80f905 7702 }
            // n = 4, score = 900
            //   eb0a                 | mov                 edx, eax
            //   8d48bf               | nop                 dword ptr [eax + eax]
            //   80f905               | inc                 ecx
            //   7702                 | movzx               eax, byte ptr [eax - 1]

        $sequence_2 = { 7704 04a9 eb0a 8d48bf 80f905 7702 }
            // n = 6, score = 900
            //   7704                 | ret                 
            //   04a9                 | inc                 eax
            //   eb0a                 | push                ebx
            //   8d48bf               | dec                 eax
            //   80f905               | sub                 esp, 0x20
            //   7702                 | dec                 eax

        $sequence_3 = { 04a9 eb0a 8d48bf 80f905 }
            // n = 4, score = 900
            //   04a9                 | add                 al, 0x5c
            //   eb0a                 | add                 al, 0x4c
            //   8d48bf               | out                 0xb2, al
            //   80f905               | add                 al, 0x23

        $sequence_4 = { 8d489f 80f905 7704 04a9 eb0a 8d48bf }
            // n = 6, score = 900
            //   8d489f               | mov                 dword ptr [esp + 0x64], eax
            //   80f905               | dec                 esp
            //   7704                 | mov                 ebp, dword ptr [ebp - 0x41]
            //   04a9                 | movups              xmm0, xmmword ptr [ecx + 0x40]
            //   eb0a                 | movups              xmm1, xmmword ptr [ecx + 0x50]
            //   8d48bf               | movaps              xmmword ptr [ebp - 0x29], xmm0

        $sequence_5 = { 8d4a9f 80f905 7705 80c2a9 eb0b 8d4abf 80f905 }
            // n = 7, score = 900
            //   8d4a9f               | mov                 dword ptr [ebx - 0x68], eax
            //   80f905               | dec                 ecx
            //   7705                 | mov                 dword ptr [ebx - 0x60], eax
            //   80c2a9               | dec                 eax
            //   eb0b                 | lea                 edx, dword ptr [0x2ae22]
            //   8d4abf               | dec                 eax
            //   80f905               | mov                 edi, edx

        $sequence_6 = { 721e 8125????????fffdffff 8125????????fffdffff 8125????????fffdffff }
            // n = 4, score = 900
            //   721e                 | dec                 ebp
            //   8125????????fffdffff     |     
            //   8125????????fffdffff     |     
            //   8125????????fffdffff     |     

        $sequence_7 = { 8d489f 80f905 7704 04a9 eb0a }
            // n = 5, score = 900
            //   8d489f               | mov                 eax, ebx
            //   80f905               | dec                 eax
            //   7704                 | mov                 edi, ebx
            //   04a9                 | dec                 eax
            //   eb0a                 | sar                 edi, 5

        $sequence_8 = { eb0a 8d48bf 80f905 7702 04c9 }
            // n = 5, score = 900
            //   eb0a                 | cmp                 ebx, dword ptr [ebp - 0x3c]
            //   8d48bf               | jb                  0xffffffbf
            //   80f905               | xor                 bl, bl
            //   7702                 | mov                 eax, dword ptr [ebp - 0x1c]
            //   04c9                 | add                 edi, 0x30

        $sequence_9 = { 80c2a9 eb0b 8d4abf 80f905 7703 80c2c9 }
            // n = 6, score = 900
            //   80c2a9               | sub                 esp, 0x30
            //   eb0b                 | dec                 eax
            //   8d4abf               | mov                 edi, ecx
            //   80f905               | dec                 eax
            //   7703                 | mov                 ecx, dword ptr [ecx]
            //   80c2c9               | inc                 ebp

    condition:
        7 of them and filesize < 422912
}