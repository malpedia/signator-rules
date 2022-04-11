rule win_rambo_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.rambo."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rambo"
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
        $sequence_0 = { 6804010000 ff15???????? ff7508 8d85fcfeffff 50 }
            // n = 5, score = 200
            //   6804010000           | push                0x104
            //   ff15????????         |                     
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8d85fcfeffff         | lea                 eax, dword ptr [ebp - 0x104]
            //   50                   | push                eax

        $sequence_1 = { 55 8bec 81ec08050000 56 6800040000 }
            // n = 5, score = 200
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec08050000         | sub                 esp, 0x508
            //   56                   | push                esi
            //   6800040000           | push                0x400

        $sequence_2 = { 56 6800040000 8d85f8faffff 6a00 }
            // n = 4, score = 200
            //   56                   | push                esi
            //   6800040000           | push                0x400
            //   8d85f8faffff         | lea                 eax, dword ptr [ebp - 0x508]
            //   6a00                 | push                0

        $sequence_3 = { 50 ff7508 ff15???????? 56 ff15???????? 8d85ecfdffff 50 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8d85ecfdffff         | lea                 eax, dword ptr [ebp - 0x214]
            //   50                   | push                eax

        $sequence_4 = { c645fd62 ff15???????? 8bf0 83c410 }
            // n = 4, score = 200
            //   c645fd62             | mov                 byte ptr [ebp - 3], 0x62
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   83c410               | add                 esp, 0x10

        $sequence_5 = { 50 ff15???????? 80a43df8faffff00 56 ff15???????? }
            // n = 5, score = 200
            //   50                   | push                eax
            //   ff15????????         |                     
            //   80a43df8faffff00     | and                 byte ptr [ebp + edi - 0x508], 0
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_6 = { 8d85f8faffff 6a01 50 ff15???????? }
            // n = 4, score = 200
            //   8d85f8faffff         | lea                 eax, dword ptr [ebp - 0x508]
            //   6a01                 | push                1
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_7 = { 8d85f8feffff 50 c645fc72 c645fd62 }
            // n = 4, score = 200
            //   8d85f8feffff         | lea                 eax, dword ptr [ebp - 0x108]
            //   50                   | push                eax
            //   c645fc72             | mov                 byte ptr [ebp - 4], 0x72
            //   c645fd62             | mov                 byte ptr [ebp - 3], 0x62

        $sequence_8 = { c684240804000013 e8???????? 50 8d8c2488000000 e8???????? 8d8c2480000000 e8???????? }
            // n = 7, score = 100
            //   c684240804000013     | mov                 byte ptr [esp + 0x408], 0x13
            //   e8????????           |                     
            //   50                   | push                eax
            //   8d8c2488000000       | lea                 ecx, dword ptr [esp + 0x88]
            //   e8????????           |                     
            //   8d8c2480000000       | lea                 ecx, dword ptr [esp + 0x80]
            //   e8????????           |                     

        $sequence_9 = { 50 8b842418010000 52 6a01 6a00 50 51 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8b842418010000       | mov                 eax, dword ptr [esp + 0x118]
            //   52                   | push                edx
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   50                   | push                eax
            //   51                   | push                ecx

        $sequence_10 = { ff15???????? 68???????? 50 ff15???????? 8b4c2408 }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   68????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b4c2408             | mov                 ecx, dword ptr [esp + 8]

        $sequence_11 = { e8???????? 33c0 8b8c24f8030000 5f 5e 5d 5b }
            // n = 7, score = 100
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   8b8c24f8030000       | mov                 ecx, dword ptr [esp + 0x3f8]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx

        $sequence_12 = { 6a40 50 e8???????? 8d4c2464 c684240004000001 }
            // n = 5, score = 100
            //   6a40                 | push                0x40
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d4c2464             | lea                 ecx, dword ptr [esp + 0x64]
            //   c684240004000001     | mov                 byte ptr [esp + 0x400], 1

        $sequence_13 = { e8???????? 89842494000000 8b442424 6a00 50 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   89842494000000       | mov                 dword ptr [esp + 0x94], eax
            //   8b442424             | mov                 eax, dword ptr [esp + 0x24]
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_14 = { c644245531 c644245637 885c2457 884c2459 c644245a47 c644245c41 }
            // n = 6, score = 100
            //   c644245531           | mov                 byte ptr [esp + 0x55], 0x31
            //   c644245637           | mov                 byte ptr [esp + 0x56], 0x37
            //   885c2457             | mov                 byte ptr [esp + 0x57], bl
            //   884c2459             | mov                 byte ptr [esp + 0x59], cl
            //   c644245a47           | mov                 byte ptr [esp + 0x5a], 0x47
            //   c644245c41           | mov                 byte ptr [esp + 0x5c], 0x41

        $sequence_15 = { 83c9ff bf???????? 33c0 8d9424f4020000 f2ae }
            // n = 5, score = 100
            // 
            //   bf????????           |                     
            //   33c0                 | xor                 eax, eax
            //   8d9424f4020000       | lea                 edx, dword ptr [esp + 0x2f4]
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]

    condition:
        7 of them and filesize < 57344
}