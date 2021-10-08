rule win_tiop_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.tiop."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tiop"
        malpedia_rule_date = "20211007"
        malpedia_hash = "e5b790e0f888f252d49063a1251ca60ec2832535"
        malpedia_version = "20211008"
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
        $sequence_0 = { 89542464 e8???????? 83c408 8d542430 8d8424b8060000 52 53 }
            // n = 7, score = 100
            //   89542464             | mov                 dword ptr [esp + 0x64], edx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8d542430             | lea                 edx, dword ptr [esp + 0x30]
            //   8d8424b8060000       | lea                 eax, dword ptr [esp + 0x6b8]
            //   52                   | push                edx
            //   53                   | push                ebx

        $sequence_1 = { 83c9ff 33c0 53 f2ae f7d1 894c2424 51 }
            // n = 7, score = 100
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   53                   | push                ebx
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   894c2424             | mov                 dword ptr [esp + 0x24], ecx
            //   51                   | push                ecx

        $sequence_2 = { 7410 50 c745fc00000000 e8???????? 83c404 8b4df4 5f }
            // n = 7, score = 100
            //   7410                 | je                  0x12
            //   50                   | push                eax
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   5f                   | pop                 edi

        $sequence_3 = { b8fc120000 e8???????? 53 56 57 33db }
            // n = 6, score = 100
            //   b8fc120000           | mov                 eax, 0x12fc
            //   e8????????           |                     
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   33db                 | xor                 ebx, ebx

        $sequence_4 = { 6a04 57 ff15???????? 8bd8 85db 7457 }
            // n = 6, score = 100
            //   6a04                 | push                4
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax
            //   85db                 | test                ebx, ebx
            //   7457                 | je                  0x59

        $sequence_5 = { 89442410 89442418 b8???????? 89442438 89442440 b8???????? 8b9c2408010000 }
            // n = 7, score = 100
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   89442418             | mov                 dword ptr [esp + 0x18], eax
            //   b8????????           |                     
            //   89442438             | mov                 dword ptr [esp + 0x38], eax
            //   89442440             | mov                 dword ptr [esp + 0x40], eax
            //   b8????????           |                     
            //   8b9c2408010000       | mov                 ebx, dword ptr [esp + 0x108]

        $sequence_6 = { 8bc5 5e 5d 5b 81c428010000 c3 8bbc2440010000 }
            // n = 7, score = 100
            //   8bc5                 | mov                 eax, ebp
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx
            //   81c428010000         | add                 esp, 0x128
            //   c3                   | ret                 
            //   8bbc2440010000       | mov                 edi, dword ptr [esp + 0x140]

        $sequence_7 = { 8d8ebc000000 c644241005 e8???????? 8d8e98000000 c644241004 e8???????? 8d4e74 }
            // n = 7, score = 100
            //   8d8ebc000000         | lea                 ecx, dword ptr [esi + 0xbc]
            //   c644241005           | mov                 byte ptr [esp + 0x10], 5
            //   e8????????           |                     
            //   8d8e98000000         | lea                 ecx, dword ptr [esi + 0x98]
            //   c644241004           | mov                 byte ptr [esp + 0x10], 4
            //   e8????????           |                     
            //   8d4e74               | lea                 ecx, dword ptr [esi + 0x74]

        $sequence_8 = { 7505 e8???????? 6a01 58 c20c00 ff25???????? ff25???????? }
            // n = 7, score = 100
            //   7505                 | jne                 7
            //   e8????????           |                     
            //   6a01                 | push                1
            //   58                   | pop                 eax
            //   c20c00               | ret                 0xc
            //   ff25????????         |                     
            //   ff25????????         |                     

        $sequence_9 = { 5d 5e 5b 81c434040000 c3 8bc6 }
            // n = 6, score = 100
            //   5d                   | pop                 ebp
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   81c434040000         | add                 esp, 0x434
            //   c3                   | ret                 
            //   8bc6                 | mov                 eax, esi

    condition:
        7 of them and filesize < 712704
}