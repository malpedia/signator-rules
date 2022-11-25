rule win_tarsip_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.tarsip."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tarsip"
        malpedia_rule_date = "20221118"
        malpedia_hash = "e0702e2e6d1d00da65c8a29a4ebacd0a4c59e1af"
        malpedia_version = "20221125"
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
        $sequence_0 = { 83c404 8b8c24e40d0000 5f 5e 5d 5b }
            // n = 6, score = 100
            //   83c404               | add                 esp, 4
            //   8b8c24e40d0000       | mov                 ecx, dword ptr [esp + 0xde4]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx

        $sequence_1 = { 52 51 ff15???????? 85c0 0f846cfeffff b8???????? }
            // n = 6, score = 100
            //   52                   | push                edx
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f846cfeffff         | je                  0xfffffe72
            //   b8????????           |                     

        $sequence_2 = { e8???????? 8d4c2418 51 8b4c2418 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   8d4c2418             | lea                 ecx, [esp + 0x18]
            //   51                   | push                ecx
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]

        $sequence_3 = { 59 85c0 7456 8b4de0 8d0c8d00704200 8901 8305????????20 }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   7456                 | je                  0x58
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   8d0c8d00704200       | lea                 ecx, [ecx*4 + 0x427000]
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8305????????20       |                     

        $sequence_4 = { 75f9 2bc2 8b9504400100 50 }
            // n = 4, score = 100
            //   75f9                 | jne                 0xfffffffb
            //   2bc2                 | sub                 eax, edx
            //   8b9504400100         | mov                 edx, dword ptr [ebp + 0x14004]
            //   50                   | push                eax

        $sequence_5 = { 74d9 b801000000 eb0b 8d5c244c e8???????? 33db 3bc3 }
            // n = 7, score = 100
            //   74d9                 | je                  0xffffffdb
            //   b801000000           | mov                 eax, 1
            //   eb0b                 | jmp                 0xd
            //   8d5c244c             | lea                 ebx, [esp + 0x4c]
            //   e8????????           |                     
            //   33db                 | xor                 ebx, ebx
            //   3bc3                 | cmp                 eax, ebx

        $sequence_6 = { 50 ff15???????? 3d02010000 750d a1???????? }
            // n = 5, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   3d02010000           | cmp                 eax, 0x102
            //   750d                 | jne                 0xf
            //   a1????????           |                     

        $sequence_7 = { e8???????? e8???????? 99 b980841e00 f7f9 6a0a 8d44240c }
            // n = 7, score = 100
            //   e8????????           |                     
            //   e8????????           |                     
            //   99                   | cdq                 
            //   b980841e00           | mov                 ecx, 0x1e8480
            //   f7f9                 | idiv                ecx
            //   6a0a                 | push                0xa
            //   8d44240c             | lea                 eax, [esp + 0xc]

        $sequence_8 = { 8b442418 0374241c 53 8d542418 52 53 53 }
            // n = 7, score = 100
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]
            //   0374241c             | add                 esi, dword ptr [esp + 0x1c]
            //   53                   | push                ebx
            //   8d542418             | lea                 edx, [esp + 0x18]
            //   52                   | push                edx
            //   53                   | push                ebx
            //   53                   | push                ebx

        $sequence_9 = { 7550 8b8618420100 57 8b3d???????? 85c0 740d 50 }
            // n = 7, score = 100
            //   7550                 | jne                 0x52
            //   8b8618420100         | mov                 eax, dword ptr [esi + 0x14218]
            //   57                   | push                edi
            //   8b3d????????         |                     
            //   85c0                 | test                eax, eax
            //   740d                 | je                  0xf
            //   50                   | push                eax

    condition:
        7 of them and filesize < 360448
}