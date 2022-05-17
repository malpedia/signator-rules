rule win_wastedloader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.wastedloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wastedloader"
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
        $sequence_0 = { 833d????????56 2bc0 6f bb1080388c fb }
            // n = 5, score = 100
            //   833d????????56       |                     
            //   2bc0                 | sub                 eax, eax
            //   6f                   | outsd               dx, dword ptr [esi]
            //   bb1080388c           | mov                 ebx, 0x8c388010
            //   fb                   | sti                 

        $sequence_1 = { 50 8b0d???????? 81e9ad0c0000 51 ff15???????? }
            // n = 5, score = 100
            //   50                   | push                eax
            //   8b0d????????         |                     
            //   81e9ad0c0000         | sub                 ecx, 0xcad
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_2 = { 005d57 4b bfb901fb2c a1???????? ac }
            // n = 5, score = 100
            //   005d57               | add                 byte ptr [ebp + 0x57], bl
            //   4b                   | dec                 ebx
            //   bfb901fb2c           | mov                 edi, 0x2cfb01b9
            //   a1????????           |                     
            //   ac                   | lodsb               al, byte ptr [esi]

        $sequence_3 = { 8b55f8 66894a52 b888000000 8b4df8 66894154 8b55f8 0fb74254 }
            // n = 7, score = 100
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   66894a52             | mov                 word ptr [edx + 0x52], cx
            //   b888000000           | mov                 eax, 0x88
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   66894154             | mov                 word ptr [ecx + 0x54], ax
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   0fb74254             | movzx               eax, word ptr [edx + 0x54]

        $sequence_4 = { 8b45f8 6689505c b9d1000000 8b55f8 66894a5e }
            // n = 5, score = 100
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   6689505c             | mov                 word ptr [eax + 0x5c], dx
            //   b9d1000000           | mov                 ecx, 0xd1
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   66894a5e             | mov                 word ptr [edx + 0x5e], cx

        $sequence_5 = { d193e13e7876 02dd ae 687b90c2e9 b748 }
            // n = 5, score = 100
            //   d193e13e7876         | rcl                 dword ptr [ebx + 0x76783ee1], 1
            //   02dd                 | add                 bl, ch
            //   ae                   | scasb               al, byte ptr es:[edi]
            //   687b90c2e9           | push                0xe9c2907b
            //   b748                 | mov                 bh, 0x48

        $sequence_6 = { 8bec 83ec08 c745f8???????? b8bd000000 8b4df8 668901 }
            // n = 6, score = 100
            //   8bec                 | mov                 ebp, esp
            //   83ec08               | sub                 esp, 8
            //   c745f8????????       |                     
            //   b8bd000000           | mov                 eax, 0xbd
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   668901               | mov                 word ptr [ecx], ax

        $sequence_7 = { f7ff bf067606bf 06 760a 42 07 ce }
            // n = 7, score = 100
            //   f7ff                 | idiv                edi
            //   bf067606bf           | mov                 edi, 0xbf067606
            //   06                   | push                es
            //   760a                 | jbe                 0xc
            //   42                   | inc                 edx
            //   07                   | pop                 es
            //   ce                   | into                

        $sequence_8 = { 9c ce e40f 33414d 85fb }
            // n = 5, score = 100
            //   9c                   | pushfd              
            //   ce                   | into                
            //   e40f                 | in                  al, 0xf
            //   33414d               | xor                 eax, dword ptr [ecx + 0x4d]
            //   85fb                 | test                ebx, edi

        $sequence_9 = { 8bec c705????????00000000 a1???????? a3???????? }
            // n = 4, score = 100
            //   8bec                 | mov                 ebp, esp
            //   c705????????00000000     |     
            //   a1????????           |                     
            //   a3????????           |                     

    condition:
        7 of them and filesize < 2677760
}