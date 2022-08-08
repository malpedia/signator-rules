rule win_industrial_spy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-08-05"
        version = "1"
        description = "Detects win.industrial_spy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.industrial_spy"
        malpedia_rule_date = "20220805"
        malpedia_hash = "6ec06c64bcfdbeda64eff021c766b4ce34542b71"
        malpedia_version = "20220808"
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
        $sequence_0 = { 428b142f 33c9 2bd6 f7d6 3bd6 0f97c1 2b542450 }
            // n = 7, score = 100
            //   428b142f             | ja                  0x2b7
            //   33c9                 | jne                 0x359
            //   2bd6                 | inc                 esp
            //   f7d6                 | movzx               ebx, word ptr [esp + 0x44]
            //   3bd6                 | jmp                 0x36f
            //   0f97c1               | shl                 edx, 0x10
            //   2b542450             | inc                 ecx

        $sequence_1 = { 48ffc2 6685c0 75ef 48ffc3 493bd8 7c91 ff15???????? }
            // n = 7, score = 100
            //   48ffc2               | mov                 eax, edx
            //   6685c0               | and                 edx, 0x3f
            //   75ef                 | dec                 eax
            //   48ffc3               | sar                 eax, 6
            //   493bd8               | jmp                 0x1948
            //   7c91                 | neg                 ecx
            //   ff15????????         |                     

        $sequence_2 = { 41c1e903 44898c2428090000 488d05690d0200 4889442420 4c8bc6 }
            // n = 5, score = 100
            //   41c1e903             | dec                 eax
            //   44898c2428090000     | sub                 edx, 1
            //   488d05690d0200       | jns                 0x1041
            //   4889442420           | inc                 ecx
            //   4c8bc6               | inc                 ebx

        $sequence_3 = { 2bc8 0f84d7fbffff 8d41ff 418b8480a8a90100 85c0 746a 413bc7 }
            // n = 7, score = 100
            //   2bc8                 | dec                 ecx
            //   0f84d7fbffff         | sar                 ebp, 6
            //   8d41ff               | dec                 esp
            //   418b8480a8a90100     | lea                 edi, [eax + eax*8]
            //   85c0                 | dec                 ecx
            //   746a                 | mov                 eax, ebp
            //   413bc7               | dec                 eax

        $sequence_4 = { 4c8d05c21b0100 488bf9 488d15c01b0100 b904000000 e8???????? 8bd3 488bcf }
            // n = 7, score = 100
            //   4c8d05c21b0100       | inc                 esp
            //   488bf9               | add                 ecx, edi
            //   488d15c01b0100       | or                  ecx, edx
            //   b904000000           | dec                 eax
            //   e8????????           |                     
            //   8bd3                 | mov                 edx, ebx
            //   488bcf               | inc                 ecx

        $sequence_5 = { 0355ec 4103d3 c1c20a 4103d0 0bc2 4133c0 0345c8 }
            // n = 7, score = 100
            //   0355ec               | shr                 eax, 3
            //   4103d3               | mov                 dword ptr [esp + 0x928], eax
            //   c1c20a               | dec                 eax
            //   4103d0               | lea                 eax, [esp + 0x280]
            //   0bc2                 | dec                 eax
            //   4133c0               | lea                 ecx, [esp + 0x480]
            //   0345c8               | xorps               xmm0, xmm0

        $sequence_6 = { 418bd1 0fafd0 418bf8 0faff8 }
            // n = 4, score = 100
            //   418bd1               | movzx               edx, byte ptr [ecx + 5]
            //   0fafd0               | inc                 ecx
            //   418bf8               | movzx               eax, byte ptr [ecx + 7]
            //   0faff8               | or                  eax, ecx

        $sequence_7 = { c3 e8???????? c70016000000 e8???????? 8bc7 ebd1 4053 }
            // n = 7, score = 100
            //   c3                   | lea                 ecx, [eax + esi*8]
            //   e8????????           |                     
            //   c70016000000         | lea                 eax, [esi*8]
            //   e8????????           |                     
            //   8bc7                 | inc                 esp
            //   ebd1                 | mov                 dword ptr [ecx + 0x10], ecx
            //   4053                 | mov                 ecx, dword ptr [ecx + 0x14]

        $sequence_8 = { c784247c01000070007400 c78424800100002e007700 c784248401000073002e00 c784248801000077007300 c784248c01000068002e00 }
            // n = 5, score = 100
            //   c784247c01000070007400     | mov    edx, ebx
            //   c78424800100002e007700     | dec    eax
            //   c784248401000073002e00     | mov    edi, ecx
            //   c784248801000077007300     | dec    ecx
            //   c784248c01000068002e00     | mov    eax, edx

        $sequence_9 = { 44338384000000 44894544 895540 89b380000000 4489b384000000 488b4df0 41ba01000000 }
            // n = 7, score = 100
            //   44338384000000       | jne                 0x815
            //   44894544             | dec                 esp
            //   895540               | lea                 ebx, [esp + 0xf0]
            //   89b380000000         | dec                 ecx
            //   4489b384000000       | mov                 ebx, dword ptr [ebx + 0x10]
            //   488b4df0             | dec                 ecx
            //   41ba01000000         | mov                 ebp, dword ptr [ebx + 0x18]

    condition:
        7 of them and filesize < 339968
}