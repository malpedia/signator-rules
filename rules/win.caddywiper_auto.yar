rule win_caddywiper_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.caddywiper."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.caddywiper"
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
        $sequence_0 = { c645d474 c645d565 c645d646 c645d769 c645d86c }
            // n = 5, score = 100
            //   c645d474             | mov                 byte ptr [ebp - 0x2c], 0x74
            //   c645d565             | mov                 byte ptr [ebp - 0x2b], 0x65
            //   c645d646             | mov                 byte ptr [ebp - 0x2a], 0x46
            //   c645d769             | mov                 byte ptr [ebp - 0x29], 0x69
            //   c645d86c             | mov                 byte ptr [ebp - 0x28], 0x6c

        $sequence_1 = { 8945f8 c7850cf8ffff09000000 c785f8f7ffff00000000 c745fcffffffff 6880070000 }
            // n = 5, score = 100
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   c7850cf8ffff09000000     | mov    dword ptr [ebp - 0x7f4], 9
            //   c785f8f7ffff00000000     | mov    dword ptr [ebp - 0x808], 0
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   6880070000           | push                0x780

        $sequence_2 = { c6857effffff69 c6857fffffff00 c6458033 c6458100 c6458232 c6458300 c645842e }
            // n = 7, score = 100
            //   c6857effffff69       | mov                 byte ptr [ebp - 0x82], 0x69
            //   c6857fffffff00       | mov                 byte ptr [ebp - 0x81], 0
            //   c6458033             | mov                 byte ptr [ebp - 0x80], 0x33
            //   c6458100             | mov                 byte ptr [ebp - 0x7f], 0
            //   c6458232             | mov                 byte ptr [ebp - 0x7e], 0x32
            //   c6458300             | mov                 byte ptr [ebp - 0x7d], 0
            //   c645842e             | mov                 byte ptr [ebp - 0x7c], 0x2e

        $sequence_3 = { c685befbffff6c c685bffbffff00 c685c0fbffff33 c685c1fbffff00 c685c2fbffff32 c685c3fbffff00 c685c4fbffff2e }
            // n = 7, score = 100
            //   c685befbffff6c       | mov                 byte ptr [ebp - 0x442], 0x6c
            //   c685bffbffff00       | mov                 byte ptr [ebp - 0x441], 0
            //   c685c0fbffff33       | mov                 byte ptr [ebp - 0x440], 0x33
            //   c685c1fbffff00       | mov                 byte ptr [ebp - 0x43f], 0
            //   c685c2fbffff32       | mov                 byte ptr [ebp - 0x43e], 0x32
            //   c685c3fbffff00       | mov                 byte ptr [ebp - 0x43d], 0
            //   c685c4fbffff2e       | mov                 byte ptr [ebp - 0x43c], 0x2e

        $sequence_4 = { c645d86c c645d965 c645da57 c645db00 8d45d0 50 8d4ddc }
            // n = 7, score = 100
            //   c645d86c             | mov                 byte ptr [ebp - 0x28], 0x6c
            //   c645d965             | mov                 byte ptr [ebp - 0x27], 0x65
            //   c645da57             | mov                 byte ptr [ebp - 0x26], 0x57
            //   c645db00             | mov                 byte ptr [ebp - 0x25], 0
            //   8d45d0               | lea                 eax, dword ptr [ebp - 0x30]
            //   50                   | push                eax
            //   8d4ddc               | lea                 ecx, dword ptr [ebp - 0x24]

        $sequence_5 = { 50 e8???????? 83c404 c645e044 c645e13a }
            // n = 5, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   c645e044             | mov                 byte ptr [ebp - 0x20], 0x44
            //   c645e13a             | mov                 byte ptr [ebp - 0x1f], 0x3a

        $sequence_6 = { 0345fc 8a08 884dfb ebce 8b5508 0355f4 c60200 }
            // n = 7, score = 100
            //   0345fc               | add                 eax, dword ptr [ebp - 4]
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   884dfb               | mov                 byte ptr [ebp - 5], cl
            //   ebce                 | jmp                 0xffffffd0
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   0355f4               | add                 edx, dword ptr [ebp - 0xc]
            //   c60200               | mov                 byte ptr [edx], 0

        $sequence_7 = { 0fbe4df7 83f95a 7f0d 8b55f8 }
            // n = 4, score = 100
            //   0fbe4df7             | movsx               ecx, byte ptr [ebp - 9]
            //   83f95a               | cmp                 ecx, 0x5a
            //   7f0d                 | jg                  0xf
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]

        $sequence_8 = { c68543ffffff00 8d8d38ffffff 51 8d55b8 52 e8???????? 83c408 }
            // n = 7, score = 100
            //   c68543ffffff00       | mov                 byte ptr [ebp - 0xbd], 0
            //   8d8d38ffffff         | lea                 ecx, dword ptr [ebp - 0xc8]
            //   51                   | push                ecx
            //   8d55b8               | lea                 edx, dword ptr [ebp - 0x48]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_9 = { c68531ffffff65 c68532ffffff67 c68533ffffff65 c68534ffffff00 6a01 }
            // n = 5, score = 100
            //   c68531ffffff65       | mov                 byte ptr [ebp - 0xcf], 0x65
            //   c68532ffffff67       | mov                 byte ptr [ebp - 0xce], 0x67
            //   c68533ffffff65       | mov                 byte ptr [ebp - 0xcd], 0x65
            //   c68534ffffff00       | mov                 byte ptr [ebp - 0xcc], 0
            //   6a01                 | push                1

    condition:
        7 of them and filesize < 33792
}