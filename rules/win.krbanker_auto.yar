rule win_krbanker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.krbanker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.krbanker"
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
        $sequence_0 = { bb40010000 e8???????? 83c410 8945cc 6801010080 }
            // n = 5, score = 400
            //   bb40010000           | mov                 ebx, 0x140
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax
            //   6801010080           | push                0x80000101

        $sequence_1 = { 50 8b5d08 8b1b 53 8b0b }
            // n = 5, score = 400
            //   50                   | push                eax
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   8b1b                 | mov                 ebx, dword ptr [ebx]
            //   53                   | push                ebx
            //   8b0b                 | mov                 ecx, dword ptr [ebx]

        $sequence_2 = { f6c420 0f8451010000 f6c440 7407 8b5508 8b1a eb03 }
            // n = 7, score = 400
            //   f6c420               | test                ah, 0x20
            //   0f8451010000         | je                  0x157
            //   f6c440               | test                ah, 0x40
            //   7407                 | je                  9
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b1a                 | mov                 ebx, dword ptr [edx]
            //   eb03                 | jmp                 5

        $sequence_3 = { c7460403400080 33c0 5e 83c408 c3 c744240400000000 8b06 }
            // n = 7, score = 400
            //   c7460403400080       | mov                 dword ptr [esi + 4], 0x80004003
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi
            //   83c408               | add                 esp, 8
            //   c3                   | ret                 
            //   c744240400000000     | mov                 dword ptr [esp + 4], 0
            //   8b06                 | mov                 eax, dword ptr [esi]

        $sequence_4 = { 8b44244c 03fd 2bdd 83f8ff 7419 48 8944244c }
            // n = 7, score = 400
            //   8b44244c             | mov                 eax, dword ptr [esp + 0x4c]
            //   03fd                 | add                 edi, ebp
            //   2bdd                 | sub                 ebx, ebp
            //   83f8ff               | cmp                 eax, -1
            //   7419                 | je                  0x1b
            //   48                   | dec                 eax
            //   8944244c             | mov                 dword ptr [esp + 0x4c], eax

        $sequence_5 = { 0f9cc3 4b 23d9 8b4838 }
            // n = 4, score = 400
            //   0f9cc3               | setl                bl
            //   4b                   | dec                 ebx
            //   23d9                 | and                 ebx, ecx
            //   8b4838               | mov                 ecx, dword ptr [eax + 0x38]

        $sequence_6 = { 6801000000 bb40010000 e8???????? 83c410 8945e0 }
            // n = 5, score = 400
            //   6801000000           | push                1
            //   bb40010000           | mov                 ebx, 0x140
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax

        $sequence_7 = { ff7508 ff15???????? 90 90 90 90 3965f8 }
            // n = 7, score = 400
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   90                   | nop                 
            //   90                   | nop                 
            //   90                   | nop                 
            //   90                   | nop                 
            //   3965f8               | cmp                 dword ptr [ebp - 8], esp

        $sequence_8 = { 6a00 684b000000 6801000000 bb40010000 e8???????? }
            // n = 5, score = 400
            //   6a00                 | push                0
            //   684b000000           | push                0x4b
            //   6801000000           | push                1
            //   bb40010000           | mov                 ebx, 0x140
            //   e8????????           |                     

        $sequence_9 = { eb08 895c2418 895c2414 8b482c 85c9 740e }
            // n = 6, score = 400
            //   eb08                 | jmp                 0xa
            //   895c2418             | mov                 dword ptr [esp + 0x18], ebx
            //   895c2414             | mov                 dword ptr [esp + 0x14], ebx
            //   8b482c               | mov                 ecx, dword ptr [eax + 0x2c]
            //   85c9                 | test                ecx, ecx
            //   740e                 | je                  0x10

    condition:
        7 of them and filesize < 1826816
}