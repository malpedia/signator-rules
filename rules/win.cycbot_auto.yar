rule win_cycbot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.cycbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cycbot"
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
        $sequence_0 = { 8945ec 8b450c 8945e4 a1???????? 53 56 8945f4 }
            // n = 7, score = 100
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   a1????????           |                     
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax

        $sequence_1 = { e8???????? 59 837dc000 7409 ff75c0 e8???????? 59 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   837dc000             | cmp                 dword ptr [ebp - 0x40], 0
            //   7409                 | je                  0xb
            //   ff75c0               | push                dword ptr [ebp - 0x40]
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_2 = { 6a08 53 53 53 56 53 ff15???????? }
            // n = 7, score = 100
            //   6a08                 | push                8
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   56                   | push                esi
            //   53                   | push                ebx
            //   ff15????????         |                     

        $sequence_3 = { a1???????? 33c5 8945fc 83a5f0fdffff00 8d85f8feffff 50 }
            // n = 6, score = 100
            //   a1????????           |                     
            //   33c5                 | xor                 eax, ebp
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   83a5f0fdffff00       | and                 dword ptr [ebp - 0x210], 0
            //   8d85f8feffff         | lea                 eax, dword ptr [ebp - 0x108]
            //   50                   | push                eax

        $sequence_4 = { c6460800 e8???????? 83c404 8bf7 3b7dbc 75ce }
            // n = 6, score = 100
            //   c6460800             | mov                 byte ptr [esi + 8], 0
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8bf7                 | mov                 esi, edi
            //   3b7dbc               | cmp                 edi, dword ptr [ebp - 0x44]
            //   75ce                 | jne                 0xffffffd0

        $sequence_5 = { 7410 8b4dcc 2bc8 8bfe 8a1401 8810 40 }
            // n = 7, score = 100
            //   7410                 | je                  0x12
            //   8b4dcc               | mov                 ecx, dword ptr [ebp - 0x34]
            //   2bc8                 | sub                 ecx, eax
            //   8bfe                 | mov                 edi, esi
            //   8a1401               | mov                 dl, byte ptr [ecx + eax]
            //   8810                 | mov                 byte ptr [eax], dl
            //   40                   | inc                 eax

        $sequence_6 = { 59 8b4dfc 8b8534eeffff 5f 5e 33cd 5b }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8b8534eeffff         | mov                 eax, dword ptr [ebp - 0x11cc]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   33cd                 | xor                 ecx, ebp
            //   5b                   | pop                 ebx

        $sequence_7 = { 33c9 3c01 0f94c1 bf00040000 57 894c2444 e8???????? }
            // n = 7, score = 100
            //   33c9                 | xor                 ecx, ecx
            //   3c01                 | cmp                 al, 1
            //   0f94c1               | sete                cl
            //   bf00040000           | mov                 edi, 0x400
            //   57                   | push                edi
            //   894c2444             | mov                 dword ptr [esp + 0x44], ecx
            //   e8????????           |                     

        $sequence_8 = { 57 33ff 8975d4 8945e8 894dec 897de4 3bf7 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   33ff                 | xor                 edi, edi
            //   8975d4               | mov                 dword ptr [ebp - 0x2c], esi
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   894dec               | mov                 dword ptr [ebp - 0x14], ecx
            //   897de4               | mov                 dword ptr [ebp - 0x1c], edi
            //   3bf7                 | cmp                 esi, edi

        $sequence_9 = { e8???????? 8bf0 8dbc2404010000 c68424480a000006 e8???????? 6a00 6a01 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   8dbc2404010000       | lea                 edi, dword ptr [esp + 0x104]
            //   c68424480a000006     | mov                 byte ptr [esp + 0xa48], 6
            //   e8????????           |                     
            //   6a00                 | push                0
            //   6a01                 | push                1

    condition:
        7 of them and filesize < 1163264
}