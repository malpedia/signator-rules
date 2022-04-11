rule win_kpot_stealer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.kpot_stealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kpot_stealer"
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
        $sequence_0 = { 3c65 7552 8d5301 8a02 3c2d }
            // n = 5, score = 500
            //   3c65                 | cmp                 al, 0x65
            //   7552                 | jne                 0x54
            //   8d5301               | lea                 edx, dword ptr [ebx + 1]
            //   8a02                 | mov                 al, byte ptr [edx]
            //   3c2d                 | cmp                 al, 0x2d

        $sequence_1 = { 50 b8???????? e8???????? 59 85c0 }
            // n = 5, score = 500
            //   50                   | push                eax
            //   b8????????           |                     
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax

        $sequence_2 = { eb03 0175fc 33f6 3975fc }
            // n = 4, score = 500
            //   eb03                 | jmp                 5
            //   0175fc               | add                 dword ptr [ebp - 4], esi
            //   33f6                 | xor                 esi, esi
            //   3975fc               | cmp                 dword ptr [ebp - 4], esi

        $sequence_3 = { 8b7508 83c6f8 894dfc 8955f8 897508 0f88c8000000 }
            // n = 6, score = 500
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   83c6f8               | add                 esi, -8
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   897508               | mov                 dword ptr [ebp + 8], esi
            //   0f88c8000000         | js                  0xce

        $sequence_4 = { 84d2 741b 80fa5c 7508 41 }
            // n = 5, score = 500
            //   84d2                 | test                dl, dl
            //   741b                 | je                  0x1d
            //   80fa5c               | cmp                 dl, 0x5c
            //   7508                 | jne                 0xa
            //   41                   | inc                 ecx

        $sequence_5 = { 8ac3 e8???????? 84c0 7505 8b55f0 eb6b }
            // n = 6, score = 500
            //   8ac3                 | mov                 al, bl
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7505                 | jne                 7
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   eb6b                 | jmp                 0x6d

        $sequence_6 = { c3 8908 894808 894804 c3 }
            // n = 5, score = 500
            //   c3                   | ret                 
            //   8908                 | mov                 dword ptr [eax], ecx
            //   894808               | mov                 dword ptr [eax + 8], ecx
            //   894804               | mov                 dword ptr [eax + 4], ecx
            //   c3                   | ret                 

        $sequence_7 = { 75f6 0fb64dff 8b45f8 3bc8 7605 fec8 8845ff }
            // n = 7, score = 500
            //   75f6                 | jne                 0xfffffff8
            //   0fb64dff             | movzx               ecx, byte ptr [ebp - 1]
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   3bc8                 | cmp                 ecx, eax
            //   7605                 | jbe                 7
            //   fec8                 | dec                 al
            //   8845ff               | mov                 byte ptr [ebp - 1], al

        $sequence_8 = { d1e8 33c2 be55555555 23c6 33d0 03c0 33c8 }
            // n = 7, score = 500
            //   d1e8                 | shr                 eax, 1
            //   33c2                 | xor                 eax, edx
            //   be55555555           | mov                 esi, 0x55555555
            //   23c6                 | and                 eax, esi
            //   33d0                 | xor                 edx, eax
            //   03c0                 | add                 eax, eax
            //   33c8                 | xor                 ecx, eax

        $sequence_9 = { 8b4d0c e8???????? 85c0 7510 }
            // n = 4, score = 500
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7510                 | jne                 0x12

    condition:
        7 of them and filesize < 219136
}