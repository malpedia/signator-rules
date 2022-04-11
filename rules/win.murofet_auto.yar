rule win_murofet_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.murofet."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.murofet"
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
        $sequence_0 = { 3c04 73ce b002 a2???????? }
            // n = 4, score = 300
            //   3c04                 | cmp                 al, 4
            //   73ce                 | jae                 0xffffffd0
            //   b002                 | mov                 al, 2
            //   a2????????           |                     

        $sequence_1 = { 8d461c 55 50 ff15???????? }
            // n = 4, score = 300
            //   8d461c               | lea                 eax, dword ptr [esi + 0x1c]
            //   55                   | push                ebp
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_2 = { 84c0 7510 e8???????? 3c04 }
            // n = 4, score = 300
            //   84c0                 | test                al, al
            //   7510                 | jne                 0x12
            //   e8????????           |                     
            //   3c04                 | cmp                 al, 4

        $sequence_3 = { 84c0 7510 e8???????? 3c04 73ce b002 a2???????? }
            // n = 7, score = 300
            //   84c0                 | test                al, al
            //   7510                 | jne                 0x12
            //   e8????????           |                     
            //   3c04                 | cmp                 al, 4
            //   73ce                 | jae                 0xffffffd0
            //   b002                 | mov                 al, 2
            //   a2????????           |                     

        $sequence_4 = { fec2 8816 e8???????? 0fb6c0 99 f7ff }
            // n = 6, score = 300
            //   fec2                 | inc                 dl
            //   8816                 | mov                 byte ptr [esi], dl
            //   e8????????           |                     
            //   0fb6c0               | movzx               eax, al
            //   99                   | cdq                 
            //   f7ff                 | idiv                edi

        $sequence_5 = { e8???????? 3c02 72e5 e8???????? a2???????? 84c0 7510 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   3c02                 | cmp                 al, 2
            //   72e5                 | jb                  0xffffffe7
            //   e8????????           |                     
            //   a2????????           |                     
            //   84c0                 | test                al, al
            //   7510                 | jne                 0x12

        $sequence_6 = { e8???????? 0fb6c0 99 f7ff }
            // n = 4, score = 300
            //   e8????????           |                     
            //   0fb6c0               | movzx               eax, al
            //   99                   | cdq                 
            //   f7ff                 | idiv                edi

        $sequence_7 = { 7420 6a00 6880000000 6a01 6a00 }
            // n = 5, score = 300
            //   7420                 | je                  0x22
            //   6a00                 | push                0
            //   6880000000           | push                0x80
            //   6a01                 | push                1
            //   6a00                 | push                0

        $sequence_8 = { 84c0 7510 e8???????? 3c04 73ce }
            // n = 5, score = 300
            //   84c0                 | test                al, al
            //   7510                 | jne                 0x12
            //   e8????????           |                     
            //   3c04                 | cmp                 al, 4
            //   73ce                 | jae                 0xffffffd0

        $sequence_9 = { fec2 8816 e8???????? 0fb6c0 99 }
            // n = 5, score = 300
            //   fec2                 | inc                 dl
            //   8816                 | mov                 byte ptr [esi], dl
            //   e8????????           |                     
            //   0fb6c0               | movzx               eax, al
            //   99                   | cdq                 

    condition:
        7 of them and filesize < 622592
}