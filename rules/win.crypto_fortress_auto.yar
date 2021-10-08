rule win_crypto_fortress_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.crypto_fortress."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crypto_fortress"
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
        $sequence_0 = { 8bec 83c4f8 53 ff35???????? e8???????? 6bc004 8945fc }
            // n = 7, score = 100
            //   8bec                 | mov                 ebp, esp
            //   83c4f8               | add                 esp, -8
            //   53                   | push                ebx
            //   ff35????????         |                     
            //   e8????????           |                     
            //   6bc004               | imul                eax, eax, 4
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_1 = { aa 3412 aa 341b aa 2c27 }
            // n = 6, score = 100
            //   aa                   | stosb               byte ptr es:[edi], al
            //   3412                 | xor                 al, 0x12
            //   aa                   | stosb               byte ptr es:[edi], al
            //   341b                 | xor                 al, 0x1b
            //   aa                   | stosb               byte ptr es:[edi], al
            //   2c27                 | sub                 al, 0x27

        $sequence_2 = { e8???????? 85c0 0f8449010000 ffb5b4feffff e8???????? }
            // n = 5, score = 100
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f8449010000         | je                  0x14f
            //   ffb5b4feffff         | push                dword ptr [ebp - 0x14c]
            //   e8????????           |                     

        $sequence_3 = { ff35???????? ff75f8 ff15???????? 68???????? 68???????? }
            // n = 5, score = 100
            //   ff35????????         |                     
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   ff15????????         |                     
            //   68????????           |                     
            //   68????????           |                     

        $sequence_4 = { 68???????? ff35???????? e8???????? 85c0 0f84c6030000 a3???????? 68???????? }
            // n = 7, score = 100
            //   68????????           |                     
            //   ff35????????         |                     
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f84c6030000         | je                  0x3cc
            //   a3????????           |                     
            //   68????????           |                     

        $sequence_5 = { a3???????? 68???????? ff35???????? e8???????? 85c0 0f84a9030000 a3???????? }
            // n = 7, score = 100
            //   a3????????           |                     
            //   68????????           |                     
            //   ff35????????         |                     
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f84a9030000         | je                  0x3af
            //   a3????????           |                     

        $sequence_6 = { 68???????? 50 50 ff15???????? 8b0d???????? 8904cdcc6a4000 }
            // n = 6, score = 100
            //   68????????           |                     
            //   50                   | push                eax
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b0d????????         |                     
            //   8904cdcc6a4000       | mov                 dword ptr [ecx*8 + 0x406acc], eax

        $sequence_7 = { ff35???????? e8???????? 85c0 0f8487020000 a3???????? 68???????? }
            // n = 6, score = 100
            //   ff35????????         |                     
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f8487020000         | je                  0x28d
            //   a3????????           |                     
            //   68????????           |                     

        $sequence_8 = { 83c4cc 56 57 c745fc503a5c00 c705????????00000000 }
            // n = 5, score = 100
            //   83c4cc               | add                 esp, -0x34
            //   56                   | push                esi
            //   57                   | push                edi
            //   c745fc503a5c00       | mov                 dword ptr [ebp - 4], 0x5c3a50
            //   c705????????00000000     |     

        $sequence_9 = { 50 ff15???????? 85c0 0f8512010000 8b4dfc 0bc9 7510 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f8512010000         | jne                 0x118
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   0bc9                 | or                  ecx, ecx
            //   7510                 | jne                 0x12

    condition:
        7 of them and filesize < 188416
}