rule win_netrepser_keylogger_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.netrepser_keylogger."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.netrepser_keylogger"
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
        $sequence_0 = { 8945ec 837dec00 0f840d020000 837d0c0d 7516 }
            // n = 5, score = 200
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   837dec00             | cmp                 dword ptr [ebp - 0x14], 0
            //   0f840d020000         | je                  0x213
            //   837d0c0d             | cmp                 dword ptr [ebp + 0xc], 0xd
            //   7516                 | jne                 0x18

        $sequence_1 = { c745f800000000 8d45f0 50 6a00 6a00 ff15???????? }
            // n = 6, score = 200
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0
            //   8d45f0               | lea                 eax, dword ptr [ebp - 0x10]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_2 = { c78578f8ffff32623366 c7857cf8ffff6837732e c78580f8ffff5f656700 c78584f8ffff00000000 8d8578f8ffff 50 8d8df0faffff }
            // n = 7, score = 200
            //   c78578f8ffff32623366     | mov    dword ptr [ebp - 0x788], 0x66336232
            //   c7857cf8ffff6837732e     | mov    dword ptr [ebp - 0x784], 0x2e733768
            //   c78580f8ffff5f656700     | mov    dword ptr [ebp - 0x780], 0x67655f
            //   c78584f8ffff00000000     | mov    dword ptr [ebp - 0x77c], 0
            //   8d8578f8ffff         | lea                 eax, dword ptr [ebp - 0x788]
            //   50                   | push                eax
            //   8d8df0faffff         | lea                 ecx, dword ptr [ebp - 0x510]

        $sequence_3 = { 817dfc17030900 7505 e9???????? 837dfc00 741a }
            // n = 5, score = 200
            //   817dfc17030900       | cmp                 dword ptr [ebp - 4], 0x90317
            //   7505                 | jne                 7
            //   e9????????           |                     
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0
            //   741a                 | je                  0x1c

        $sequence_4 = { 7d12 33d2 8b85d8fcffff 66899445e0fcffff }
            // n = 4, score = 200
            //   7d12                 | jge                 0x14
            //   33d2                 | xor                 edx, edx
            //   8b85d8fcffff         | mov                 eax, dword ptr [ebp - 0x328]
            //   66899445e0fcffff     | mov                 word ptr [ebp + eax*2 - 0x320], dx

        $sequence_5 = { c78564e4ffff202f7120 c78568e4ffff00000000 8d8560e4ffff 50 8d8df0f6ffff }
            // n = 5, score = 200
            //   c78564e4ffff202f7120     | mov    dword ptr [ebp - 0x1b9c], 0x20712f20
            //   c78568e4ffff00000000     | mov    dword ptr [ebp - 0x1b98], 0
            //   8d8560e4ffff         | lea                 eax, dword ptr [ebp - 0x1ba0]
            //   50                   | push                eax
            //   8d8df0f6ffff         | lea                 ecx, dword ptr [ebp - 0x910]

        $sequence_6 = { c645f973 c645fa49 c645fb64 c645fc00 8d45e4 }
            // n = 5, score = 200
            //   c645f973             | mov                 byte ptr [ebp - 7], 0x73
            //   c645fa49             | mov                 byte ptr [ebp - 6], 0x49
            //   c645fb64             | mov                 byte ptr [ebp - 5], 0x64
            //   c645fc00             | mov                 byte ptr [ebp - 4], 0
            //   8d45e4               | lea                 eax, dword ptr [ebp - 0x1c]

        $sequence_7 = { 8b0d???????? 51 e8???????? 83c404 8b55fc 8d441202 50 }
            // n = 7, score = 200
            //   8b0d????????         |                     
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8d441202             | lea                 eax, dword ptr [edx + edx + 2]
            //   50                   | push                eax

        $sequence_8 = { 8d642400 8b749500 8934c8 895cc804 }
            // n = 4, score = 100
            //   8d642400             | lea                 esp, dword ptr [esp]
            //   8b749500             | mov                 esi, dword ptr [ebp + edx*4]
            //   8934c8               | mov                 dword ptr [eax + ecx*8], esi
            //   895cc804             | mov                 dword ptr [eax + ecx*8 + 4], ebx

        $sequence_9 = { 8bd0 e8???????? 8d542414 52 e8???????? }
            // n = 5, score = 100
            //   8bd0                 | mov                 edx, eax
            //   e8????????           |                     
            //   8d542414             | lea                 edx, dword ptr [esp + 0x14]
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_10 = { 83c408 c3 8b442410 8b701c 8bcf }
            // n = 5, score = 100
            //   83c408               | add                 esp, 8
            //   c3                   | ret                 
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   8b701c               | mov                 esi, dword ptr [eax + 0x1c]
            //   8bcf                 | mov                 ecx, edi

        $sequence_11 = { a1???????? 55 8b6c244c 85c0 7550 3905???????? 7509 }
            // n = 7, score = 100
            //   a1????????           |                     
            //   55                   | push                ebp
            //   8b6c244c             | mov                 ebp, dword ptr [esp + 0x4c]
            //   85c0                 | test                eax, eax
            //   7550                 | jne                 0x52
            //   3905????????         |                     
            //   7509                 | jne                 0xb

        $sequence_12 = { c7442408536c6565 c744240c70000000 ff15???????? a3???????? }
            // n = 4, score = 100
            //   c7442408536c6565     | mov                 dword ptr [esp + 8], 0x65656c53
            //   c744240c70000000     | mov                 dword ptr [esp + 0xc], 0x70
            //   ff15????????         |                     
            //   a3????????           |                     

        $sequence_13 = { 51 e8???????? 6a04 8d542424 52 }
            // n = 5, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   6a04                 | push                4
            //   8d542424             | lea                 edx, dword ptr [esp + 0x24]
            //   52                   | push                edx

        $sequence_14 = { c74424106b656e50 c744241472697669 c74424186c656765 c744241c73000000 ff15???????? a3???????? 6a00 }
            // n = 7, score = 100
            //   c74424106b656e50     | mov                 dword ptr [esp + 0x10], 0x506e656b
            //   c744241472697669     | mov                 dword ptr [esp + 0x14], 0x69766972
            //   c74424186c656765     | mov                 dword ptr [esp + 0x18], 0x6567656c
            //   c744241c73000000     | mov                 dword ptr [esp + 0x1c], 0x73
            //   ff15????????         |                     
            //   a3????????           |                     
            //   6a00                 | push                0

        $sequence_15 = { 837c240c05 7540 837c241002 7539 6a05 ff15???????? }
            // n = 6, score = 100
            //   837c240c05           | cmp                 dword ptr [esp + 0xc], 5
            //   7540                 | jne                 0x42
            //   837c241002           | cmp                 dword ptr [esp + 0x10], 2
            //   7539                 | jne                 0x3b
            //   6a05                 | push                5
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 303104
}