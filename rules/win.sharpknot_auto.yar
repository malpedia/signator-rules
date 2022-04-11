rule win_sharpknot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.sharpknot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sharpknot"
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
        $sequence_0 = { 68???????? e8???????? 68???????? e8???????? 83c408 68???????? 57 }
            // n = 7, score = 100
            //   68????????           |                     
            //   e8????????           |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   68????????           |                     
            //   57                   | push                edi

        $sequence_1 = { 750b c1e602 8b86e8dc4000 eb09 }
            // n = 4, score = 100
            //   750b                 | jne                 0xd
            //   c1e602               | shl                 esi, 2
            //   8b86e8dc4000         | mov                 eax, dword ptr [esi + 0x40dce8]
            //   eb09                 | jmp                 0xb

        $sequence_2 = { 3bef 7e31 be???????? eb06 8b15???????? 8b0cba 6a0a }
            // n = 7, score = 100
            //   3bef                 | cmp                 ebp, edi
            //   7e31                 | jle                 0x33
            //   be????????           |                     
            //   eb06                 | jmp                 8
            //   8b15????????         |                     
            //   8b0cba               | mov                 ecx, dword ptr [edx + edi*4]
            //   6a0a                 | push                0xa

        $sequence_3 = { e8???????? 85c0 753f 8b44242c 8b4c2430 85c0 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   753f                 | jne                 0x41
            //   8b44242c             | mov                 eax, dword ptr [esp + 0x2c]
            //   8b4c2430             | mov                 ecx, dword ptr [esp + 0x30]
            //   85c0                 | test                eax, eax

        $sequence_4 = { 8b44242c 8b4c2430 85c0 7c20 7f08 }
            // n = 5, score = 100
            //   8b44242c             | mov                 eax, dword ptr [esp + 0x2c]
            //   8b4c2430             | mov                 ecx, dword ptr [esp + 0x30]
            //   85c0                 | test                eax, eax
            //   7c20                 | jl                  0x22
            //   7f08                 | jg                  0xa

        $sequence_5 = { 83c610 83ff04 897c2440 89742410 0f8c56fbffff 8b84245c040000 5d }
            // n = 7, score = 100
            //   83c610               | add                 esi, 0x10
            //   83ff04               | cmp                 edi, 4
            //   897c2440             | mov                 dword ptr [esp + 0x40], edi
            //   89742410             | mov                 dword ptr [esp + 0x10], esi
            //   0f8c56fbffff         | jl                  0xfffffb5c
            //   8b84245c040000       | mov                 eax, dword ptr [esp + 0x45c]
            //   5d                   | pop                 ebp

        $sequence_6 = { ff15???????? 8d542410 6a00 52 55 57 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   8d542410             | lea                 edx, dword ptr [esp + 0x10]
            //   6a00                 | push                0
            //   52                   | push                edx
            //   55                   | push                ebp
            //   57                   | push                edi

        $sequence_7 = { e8???????? 8b9c24600c0000 83c40c 8d842428020000 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   8b9c24600c0000       | mov                 ebx, dword ptr [esp + 0xc60]
            //   83c40c               | add                 esp, 0xc
            //   8d842428020000       | lea                 eax, dword ptr [esp + 0x228]

        $sequence_8 = { c21000 8b15???????? 8b4204 80382d 0f84b7000000 893d???????? }
            // n = 6, score = 100
            //   c21000               | ret                 0x10
            //   8b15????????         |                     
            //   8b4204               | mov                 eax, dword ptr [edx + 4]
            //   80382d               | cmp                 byte ptr [eax], 0x2d
            //   0f84b7000000         | je                  0xbd
            //   893d????????         |                     

        $sequence_9 = { 5f 5d 85c0 68???????? 7522 8d44240c 50 }
            // n = 7, score = 100
            //   5f                   | pop                 edi
            //   5d                   | pop                 ebp
            //   85c0                 | test                eax, eax
            //   68????????           |                     
            //   7522                 | jne                 0x24
            //   8d44240c             | lea                 eax, dword ptr [esp + 0xc]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 1032192
}