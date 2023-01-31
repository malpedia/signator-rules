rule win_rumish_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.rumish."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rumish"
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
        $sequence_0 = { 8bc3 e9???????? d1e2 837d08ff 7408 8b4508 8945fc }
            // n = 7, score = 100
            //   8bc3                 | mov                 eax, ebx
            //   e9????????           |                     
            //   d1e2                 | shl                 edx, 1
            //   837d08ff             | cmp                 dword ptr [ebp + 8], -1
            //   7408                 | je                  0xa
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_1 = { e8???????? 8bf0 8b4df0 51 8d4dd8 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   51                   | push                ecx
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]

        $sequence_2 = { dae9 dfe0 f6c444 7a04 c645ff01 0fb655ff 85d2 }
            // n = 7, score = 100
            //   dae9                 | fucompp             
            //   dfe0                 | fnstsw              ax
            //   f6c444               | test                ah, 0x44
            //   7a04                 | jp                  6
            //   c645ff01             | mov                 byte ptr [ebp - 1], 1
            //   0fb655ff             | movzx               edx, byte ptr [ebp - 1]
            //   85d2                 | test                edx, edx

        $sequence_3 = { 6a03 51 d905???????? d91c24 e8???????? 83c408 e8???????? }
            // n = 7, score = 100
            //   6a03                 | push                3
            //   51                   | push                ecx
            //   d905????????         |                     
            //   d91c24               | fstp                dword ptr [esp]
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   e8????????           |                     

        $sequence_4 = { c1e004 03450c 50 8b4dbc 8b5110 52 8b450c }
            // n = 7, score = 100
            //   c1e004               | shl                 eax, 4
            //   03450c               | add                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   8b4dbc               | mov                 ecx, dword ptr [ebp - 0x44]
            //   8b5110               | mov                 edx, dword ptr [ecx + 0x10]
            //   52                   | push                edx
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_5 = { 6a0c 6a00 8d4dd0 e8???????? 50 8b9574ffffff 52 }
            // n = 7, score = 100
            //   6a0c                 | push                0xc
            //   6a00                 | push                0
            //   8d4dd0               | lea                 ecx, [ebp - 0x30]
            //   e8????????           |                     
            //   50                   | push                eax
            //   8b9574ffffff         | mov                 edx, dword ptr [ebp - 0x8c]
            //   52                   | push                edx

        $sequence_6 = { 895590 c745a000000000 837d9000 7f14 7c09 817d8c81857467 7309 }
            // n = 7, score = 100
            //   895590               | mov                 dword ptr [ebp - 0x70], edx
            //   c745a000000000       | mov                 dword ptr [ebp - 0x60], 0
            //   837d9000             | cmp                 dword ptr [ebp - 0x70], 0
            //   7f14                 | jg                  0x16
            //   7c09                 | jl                  0xb
            //   817d8c81857467       | cmp                 dword ptr [ebp - 0x74], 0x67748581
            //   7309                 | jae                 0xb

        $sequence_7 = { 898d28ffffff 83bd28ffffff08 7774 8b9528ffffff ff24952cf54300 68???????? 8d4d94 }
            // n = 7, score = 100
            //   898d28ffffff         | mov                 dword ptr [ebp - 0xd8], ecx
            //   83bd28ffffff08       | cmp                 dword ptr [ebp - 0xd8], 8
            //   7774                 | ja                  0x76
            //   8b9528ffffff         | mov                 edx, dword ptr [ebp - 0xd8]
            //   ff24952cf54300       | jmp                 dword ptr [edx*4 + 0x43f52c]
            //   68????????           |                     
            //   8d4d94               | lea                 ecx, [ebp - 0x6c]

        $sequence_8 = { 8b4dfc 8b4204 ffd0 0fb6c8 85c9 7414 8b55fc }
            // n = 7, score = 100
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8b4204               | mov                 eax, dword ptr [edx + 4]
            //   ffd0                 | call                eax
            //   0fb6c8               | movzx               ecx, al
            //   85c9                 | test                ecx, ecx
            //   7414                 | je                  0x16
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]

        $sequence_9 = { 8b4db4 51 8d4dbc e8???????? 8bc8 }
            // n = 5, score = 100
            //   8b4db4               | mov                 ecx, dword ptr [ebp - 0x4c]
            //   51                   | push                ecx
            //   8d4dbc               | lea                 ecx, [ebp - 0x44]
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax

    condition:
        7 of them and filesize < 770048
}