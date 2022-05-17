rule win_snifula_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.snifula."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.snifula"
        malpedia_rule_date = "20220513"
        malpedia_hash = "7f4b2229e6ae614d86d74917f6d5b41890e62a26"
        malpedia_version = "20220516"
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
        $sequence_0 = { 83ec10 834dfcff 56 8b7508 8b4604 8b4e10 8945f4 }
            // n = 7, score = 200
            //   83ec10               | sub                 esp, 0x10
            //   834dfcff             | or                  dword ptr [ebp - 4], 0xffffffff
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   8b4e10               | mov                 ecx, dword ptr [esi + 0x10]
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax

        $sequence_1 = { e8???????? ebc9 6aff 6a00 8d45f8 50 6a02 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   ebc9                 | jmp                 0xffffffcb
            //   6aff                 | push                -1
            //   6a00                 | push                0
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   6a02                 | push                2

        $sequence_2 = { 33c0 e9???????? 8d4540 50 3bfb 7404 }
            // n = 6, score = 200
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   8d4540               | lea                 eax, [ebp + 0x40]
            //   50                   | push                eax
            //   3bfb                 | cmp                 edi, ebx
            //   7404                 | je                  6

        $sequence_3 = { c20c00 56 ff742408 ff15???????? 83c003 50 6a40 }
            // n = 7, score = 200
            //   c20c00               | ret                 0xc
            //   56                   | push                esi
            //   ff742408             | push                dword ptr [esp + 8]
            //   ff15????????         |                     
            //   83c003               | add                 eax, 3
            //   50                   | push                eax
            //   6a40                 | push                0x40

        $sequence_4 = { ff7508 e8???????? 8945e4 85c0 741c 3945fc 7517 }
            // n = 7, score = 200
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   85c0                 | test                eax, eax
            //   741c                 | je                  0x1e
            //   3945fc               | cmp                 dword ptr [ebp - 4], eax
            //   7517                 | jne                 0x19

        $sequence_5 = { 85ff 742d 56 ff7508 6a00 6800040000 ff15???????? }
            // n = 7, score = 200
            //   85ff                 | test                edi, edi
            //   742d                 | je                  0x2f
            //   56                   | push                esi
            //   ff7508               | push                dword ptr [ebp + 8]
            //   6a00                 | push                0
            //   6800040000           | push                0x400
            //   ff15????????         |                     

        $sequence_6 = { eb10 c68565ffffff04 eb07 c68565ffffff07 6a00 ff7578 }
            // n = 6, score = 200
            //   eb10                 | jmp                 0x12
            //   c68565ffffff04       | mov                 byte ptr [ebp - 0x9b], 4
            //   eb07                 | jmp                 9
            //   c68565ffffff07       | mov                 byte ptr [ebp - 0x9b], 7
            //   6a00                 | push                0
            //   ff7578               | push                dword ptr [ebp + 0x78]

        $sequence_7 = { ff15???????? 85c0 7517 68???????? ff74241c ff15???????? }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7517                 | jne                 0x19
            //   68????????           |                     
            //   ff74241c             | push                dword ptr [esp + 0x1c]
            //   ff15????????         |                     

        $sequence_8 = { 8d0446 50 53 ff15???????? eb05 33c0 668903 }
            // n = 7, score = 200
            //   8d0446               | lea                 eax, [esi + eax*2]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   eb05                 | jmp                 7
            //   33c0                 | xor                 eax, eax
            //   668903               | mov                 word ptr [ebx], ax

        $sequence_9 = { 6a02 ffd3 85c0 74b9 5e 8b4f28 }
            // n = 6, score = 200
            //   6a02                 | push                2
            //   ffd3                 | call                ebx
            //   85c0                 | test                eax, eax
            //   74b9                 | je                  0xffffffbb
            //   5e                   | pop                 esi
            //   8b4f28               | mov                 ecx, dword ptr [edi + 0x28]

    condition:
        7 of them and filesize < 188416
}