rule win_danabot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.danabot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.danabot"
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
        $sequence_0 = { 7405 83e804 8b00 83f814 7e18 8b45fc 50 }
            // n = 7, score = 400
            //   7405                 | je                  7
            //   83e804               | sub                 eax, 4
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   83f814               | cmp                 eax, 0x14
            //   7e18                 | jle                 0x1a
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax

        $sequence_1 = { 8d45e6 b90e000000 e8???????? 33c0 5a 59 }
            // n = 6, score = 400
            //   8d45e6               | lea                 eax, dword ptr [ebp - 0x1a]
            //   b90e000000           | mov                 ecx, 0xe
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   5a                   | pop                 edx
            //   59                   | pop                 ecx

        $sequence_2 = { 8b03 50 8b44242c 50 6a14 }
            // n = 5, score = 400
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   50                   | push                eax
            //   8b44242c             | mov                 eax, dword ptr [esp + 0x2c]
            //   50                   | push                eax
            //   6a14                 | push                0x14

        $sequence_3 = { 8bf8 33db 85f6 7e2f 8bc6 e8???????? }
            // n = 6, score = 400
            //   8bf8                 | mov                 edi, eax
            //   33db                 | xor                 ebx, ebx
            //   85f6                 | test                esi, esi
            //   7e2f                 | jle                 0x31
            //   8bc6                 | mov                 eax, esi
            //   e8????????           |                     

        $sequence_4 = { 56 8bf1 8bda 8945fc 8d45fc e8???????? }
            // n = 6, score = 400
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   8bda                 | mov                 ebx, edx
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8d45fc               | lea                 eax, dword ptr [ebp - 4]
            //   e8????????           |                     

        $sequence_5 = { 50 8b44243c 50 6a06 684f7ea86f 8bc3 }
            // n = 6, score = 400
            //   50                   | push                eax
            //   8b44243c             | mov                 eax, dword ptr [esp + 0x3c]
            //   50                   | push                eax
            //   6a06                 | push                6
            //   684f7ea86f           | push                0x6fa87e4f
            //   8bc3                 | mov                 eax, ebx

        $sequence_6 = { 85c0 743b 33db 8bc2 85c0 }
            // n = 5, score = 400
            //   85c0                 | test                eax, eax
            //   743b                 | je                  0x3d
            //   33db                 | xor                 ebx, ebx
            //   8bc2                 | mov                 eax, edx
            //   85c0                 | test                eax, eax

        $sequence_7 = { e8???????? 8d45f8 e8???????? bb???????? 33c0 55 }
            // n = 6, score = 400
            //   e8????????           |                     
            //   8d45f8               | lea                 eax, dword ptr [ebp - 8]
            //   e8????????           |                     
            //   bb????????           |                     
            //   33c0                 | xor                 eax, eax
            //   55                   | push                ebp

        $sequence_8 = { 8b0424 8b400c 894500 8d442418 b940000000 }
            // n = 5, score = 400
            //   8b0424               | mov                 eax, dword ptr [esp]
            //   8b400c               | mov                 eax, dword ptr [eax + 0xc]
            //   894500               | mov                 dword ptr [ebp], eax
            //   8d442418             | lea                 eax, dword ptr [esp + 0x18]
            //   b940000000           | mov                 ecx, 0x40

        $sequence_9 = { c3 55 8bec b90a000000 6a00 6a00 49 }
            // n = 7, score = 400
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   b90a000000           | mov                 ecx, 0xa
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   49                   | dec                 ecx

    condition:
        7 of them and filesize < 237568
}