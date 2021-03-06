rule win_murofet_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.murofet."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.murofet"
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
        $sequence_0 = { e8???????? e8???????? 3c02 72e5 e8???????? a2???????? 84c0 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   e8????????           |                     
            //   3c02                 | cmp                 al, 2
            //   72e5                 | jb                  0xffffffe7
            //   e8????????           |                     
            //   a2????????           |                     
            //   84c0                 | test                al, al

        $sequence_1 = { 56 ff15???????? c6443eff00 83f8ff 7509 56 ff15???????? }
            // n = 7, score = 300
            //   56                   | push                esi
            //   ff15????????         |                     
            //   c6443eff00           | mov                 byte ptr [esi + edi - 1], 0
            //   83f8ff               | cmp                 eax, -1
            //   7509                 | jne                 0xb
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_2 = { e8???????? a2???????? 84c0 7510 e8???????? }
            // n = 5, score = 300
            //   e8????????           |                     
            //   a2????????           |                     
            //   84c0                 | test                al, al
            //   7510                 | jne                 0x12
            //   e8????????           |                     

        $sequence_3 = { 6a10 8d4624 55 50 ff15???????? 83c40c }
            // n = 6, score = 300
            //   6a10                 | push                0x10
            //   8d4624               | lea                 eax, [esi + 0x24]
            //   55                   | push                ebp
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_4 = { 7535 56 be???????? 56 }
            // n = 4, score = 300
            //   7535                 | jne                 0x37
            //   56                   | push                esi
            //   be????????           |                     
            //   56                   | push                esi

        $sequence_5 = { 3c02 72e5 e8???????? a2???????? 84c0 7510 e8???????? }
            // n = 7, score = 300
            //   3c02                 | cmp                 al, 2
            //   72e5                 | jb                  0xffffffe7
            //   e8????????           |                     
            //   a2????????           |                     
            //   84c0                 | test                al, al
            //   7510                 | jne                 0x12
            //   e8????????           |                     

        $sequence_6 = { 57 56 ff15???????? c6443eff00 83f8ff 7509 56 }
            // n = 7, score = 300
            //   57                   | push                edi
            //   56                   | push                esi
            //   ff15????????         |                     
            //   c6443eff00           | mov                 byte ptr [esi + edi - 1], 0
            //   83f8ff               | cmp                 eax, -1
            //   7509                 | jne                 0xb
            //   56                   | push                esi

        $sequence_7 = { 50 53 57 56 ff15???????? c6443eff00 }
            // n = 6, score = 300
            //   50                   | push                eax
            //   53                   | push                ebx
            //   57                   | push                edi
            //   56                   | push                esi
            //   ff15????????         |                     
            //   c6443eff00           | mov                 byte ptr [esi + edi - 1], 0

        $sequence_8 = { a2???????? 84c0 7510 e8???????? 3c04 73ce }
            // n = 6, score = 300
            //   a2????????           |                     
            //   84c0                 | test                al, al
            //   7510                 | jne                 0x12
            //   e8????????           |                     
            //   3c04                 | cmp                 al, 4
            //   73ce                 | jae                 0xffffffd0

        $sequence_9 = { 56 ff15???????? c6443eff00 83f8ff 7509 56 }
            // n = 6, score = 300
            //   56                   | push                esi
            //   ff15????????         |                     
            //   c6443eff00           | mov                 byte ptr [esi + edi - 1], 0
            //   83f8ff               | cmp                 eax, -1
            //   7509                 | jne                 0xb
            //   56                   | push                esi

    condition:
        7 of them and filesize < 622592
}