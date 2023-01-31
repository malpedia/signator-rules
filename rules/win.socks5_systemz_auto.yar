rule win_socks5_systemz_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.socks5_systemz."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.socks5_systemz"
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
        $sequence_0 = { 33c0 398104020000 0f94c0 c3 33c0 }
            // n = 5, score = 200
            //   33c0                 | xor                 eax, eax
            //   398104020000         | cmp                 dword ptr [ecx + 0x204], eax
            //   0f94c0               | sete                al
            //   c3                   | ret                 
            //   33c0                 | xor                 eax, eax

        $sequence_1 = { 83ec10 894df0 c745fc01000000 8b45f0 8b4804 }
            // n = 5, score = 200
            //   83ec10               | sub                 esp, 0x10
            //   894df0               | mov                 dword ptr [ebp - 0x10], ecx
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]

        $sequence_2 = { c68547feffffc0 c68548feffff85 c68549feffff89 c6854afeffff88 c6854bfeffff88 c6854cfeffff83 }
            // n = 6, score = 200
            //   c68547feffffc0       | mov                 byte ptr [ebp - 0x1b9], 0xc0
            //   c68548feffff85       | mov                 byte ptr [ebp - 0x1b8], 0x85
            //   c68549feffff89       | mov                 byte ptr [ebp - 0x1b7], 0x89
            //   c6854afeffff88       | mov                 byte ptr [ebp - 0x1b6], 0x88
            //   c6854bfeffff88       | mov                 byte ptr [ebp - 0x1b5], 0x88
            //   c6854cfeffff83       | mov                 byte ptr [ebp - 0x1b4], 0x83

        $sequence_3 = { 8d4804 e8???????? 8bf0 85f6 743f }
            // n = 5, score = 200
            //   8d4804               | lea                 ecx, [eax + 4]
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   743f                 | je                  0x41

        $sequence_4 = { 51 33db 8d451c 8bcc }
            // n = 4, score = 200
            //   51                   | push                ecx
            //   33db                 | xor                 ebx, ebx
            //   8d451c               | lea                 eax, [ebp + 0x1c]
            //   8bcc                 | mov                 ecx, esp

        $sequence_5 = { 84c0 7504 fec0 eb1c }
            // n = 4, score = 200
            //   84c0                 | test                al, al
            //   7504                 | jne                 6
            //   fec0                 | inc                 al
            //   eb1c                 | jmp                 0x1e

        $sequence_6 = { 8995d4fdffff 68???????? ff15???????? b90e000000 }
            // n = 4, score = 200
            //   8995d4fdffff         | mov                 dword ptr [ebp - 0x22c], edx
            //   68????????           |                     
            //   ff15????????         |                     
            //   b90e000000           | mov                 ecx, 0xe

        $sequence_7 = { c68594feffff92 c68595feffffb9 c68596feffff8f c68597feffff82 }
            // n = 4, score = 200
            //   c68594feffff92       | mov                 byte ptr [ebp - 0x16c], 0x92
            //   c68595feffffb9       | mov                 byte ptr [ebp - 0x16b], 0xb9
            //   c68596feffff8f       | mov                 byte ptr [ebp - 0x16a], 0x8f
            //   c68597feffff82       | mov                 byte ptr [ebp - 0x169], 0x82

    condition:
        7 of them and filesize < 491520
}