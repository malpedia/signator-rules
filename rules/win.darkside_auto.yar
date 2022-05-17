rule win_darkside_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.darkside."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkside"
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
        $sequence_0 = { 59 5b 5d c20c00 55 }
            // n = 5, score = 1100
            //   59                   | pop                 ecx
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c20c00               | ret                 0xc
            //   55                   | push                ebp

        $sequence_1 = { 85d2 7407 52 57 e8???????? 5f 5e }
            // n = 7, score = 1100
            //   85d2                 | test                edx, edx
            //   7407                 | je                  9
            //   52                   | push                edx
            //   57                   | push                edi
            //   e8????????           |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_2 = { 7418 8bd8 68ff000000 57 }
            // n = 4, score = 1100
            //   7418                 | je                  0x1a
            //   8bd8                 | mov                 ebx, eax
            //   68ff000000           | push                0xff
            //   57                   | push                edi

        $sequence_3 = { 75d2 5f 5e 5a 59 }
            // n = 5, score = 1100
            //   75d2                 | jne                 0xffffffd4
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5a                   | pop                 edx
            //   59                   | pop                 ecx

        $sequence_4 = { 8bec 53 51 52 56 57 b9f0000000 }
            // n = 7, score = 1100
            //   8bec                 | mov                 ebp, esp
            //   53                   | push                ebx
            //   51                   | push                ecx
            //   52                   | push                edx
            //   56                   | push                esi
            //   57                   | push                edi
            //   b9f0000000           | mov                 ecx, 0xf0

        $sequence_5 = { 57 b9f0000000 be???????? 8b4508 8b10 8b5804 }
            // n = 6, score = 1100
            //   57                   | push                edi
            //   b9f0000000           | mov                 ecx, 0xf0
            //   be????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   8b5804               | mov                 ebx, dword ptr [eax + 4]

        $sequence_6 = { 5a 59 5b 5d c20c00 }
            // n = 5, score = 1100
            //   5a                   | pop                 edx
            //   59                   | pop                 ecx
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c20c00               | ret                 0xc

        $sequence_7 = { 895c0e04 893c0e 81ea10101010 2d10101010 81eb10101010 }
            // n = 5, score = 1100
            //   895c0e04             | mov                 dword ptr [esi + ecx + 4], ebx
            //   893c0e               | mov                 dword ptr [esi + ecx], edi
            //   81ea10101010         | sub                 edx, 0x10101010
            //   2d10101010           | sub                 eax, 0x10101010
            //   81eb10101010         | sub                 ebx, 0x10101010

        $sequence_8 = { 75ea 85d2 7407 52 57 }
            // n = 5, score = 1100
            //   75ea                 | jne                 0xffffffec
            //   85d2                 | test                edx, edx
            //   7407                 | je                  9
            //   52                   | push                edx
            //   57                   | push                edi

        $sequence_9 = { 7407 52 57 e8???????? 5f 5e }
            // n = 6, score = 1100
            //   7407                 | je                  9
            //   52                   | push                edx
            //   57                   | push                edi
            //   e8????????           |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

    condition:
        7 of them and filesize < 286720
}