rule win_murofet_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.murofet."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.murofet"
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
        $sequence_0 = { 7420 6a00 6880000000 6a01 6a00 }
            // n = 5, score = 300
            //   7420                 | je                  0x22
            //   6a00                 | push                0
            //   6880000000           | push                0x80
            //   6a01                 | push                1
            //   6a00                 | push                0

        $sequence_1 = { 3c04 73ce b002 a2???????? }
            // n = 4, score = 300
            //   3c04                 | cmp                 al, 4
            //   73ce                 | jae                 0xffffffd0
            //   b002                 | mov                 al, 2
            //   a2????????           |                     

        $sequence_2 = { 6a10 8d4624 55 50 }
            // n = 4, score = 300
            //   6a10                 | push                0x10
            //   8d4624               | lea                 eax, [esi + 0x24]
            //   55                   | push                ebp
            //   50                   | push                eax

        $sequence_3 = { 7510 e8???????? 3c04 73ce b002 }
            // n = 5, score = 300
            //   7510                 | jne                 0x12
            //   e8????????           |                     
            //   3c04                 | cmp                 al, 4
            //   73ce                 | jae                 0xffffffd0
            //   b002                 | mov                 al, 2

        $sequence_4 = { e8???????? 3c02 72e5 e8???????? a2???????? 84c0 7510 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   3c02                 | cmp                 al, 2
            //   72e5                 | jb                  0xffffffe7
            //   e8????????           |                     
            //   a2????????           |                     
            //   84c0                 | test                al, al
            //   7510                 | jne                 0x12

        $sequence_5 = { 84c0 7510 e8???????? 3c04 73ce b002 a2???????? }
            // n = 7, score = 300
            //   84c0                 | test                al, al
            //   7510                 | jne                 0x12
            //   e8????????           |                     
            //   3c04                 | cmp                 al, 4
            //   73ce                 | jae                 0xffffffd0
            //   b002                 | mov                 al, 2
            //   a2????????           |                     

        $sequence_6 = { 50 53 57 56 ff15???????? c6443eff00 83f8ff }
            // n = 7, score = 300
            //   50                   | push                eax
            //   53                   | push                ebx
            //   57                   | push                edi
            //   56                   | push                esi
            //   ff15????????         |                     
            //   c6443eff00           | mov                 byte ptr [esi + edi - 1], 0
            //   83f8ff               | cmp                 eax, -1

        $sequence_7 = { e8???????? 3c02 72e5 e8???????? }
            // n = 4, score = 300
            //   e8????????           |                     
            //   3c02                 | cmp                 al, 2
            //   72e5                 | jb                  0xffffffe7
            //   e8????????           |                     

        $sequence_8 = { c3 e8???????? 33c0 c20400 55 8bec 83ec68 }
            // n = 7, score = 300
            //   c3                   | ret                 
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   c20400               | ret                 4
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec68               | sub                 esp, 0x68

        $sequence_9 = { e8???????? 32c0 eb43 be30750000 56 }
            // n = 5, score = 300
            //   e8????????           |                     
            //   32c0                 | xor                 al, al
            //   eb43                 | jmp                 0x45
            //   be30750000           | mov                 esi, 0x7530
            //   56                   | push                esi

    condition:
        7 of them and filesize < 622592
}