rule win_prometei_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.prometei."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prometei"
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
        $sequence_0 = { dfb734381320 f1 a5 90 }
            // n = 4, score = 100
            //   dfb734381320         | fbstp               dword ptr [edi + 0x20133834]
            //   f1                   | int1                
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   90                   | nop                 

        $sequence_1 = { 897004 8b75fc 894808 8b4dd8 89500c b801000000 }
            // n = 6, score = 100
            //   897004               | mov                 dword ptr [eax + 4], esi
            //   8b75fc               | mov                 esi, dword ptr [ebp - 4]
            //   894808               | mov                 dword ptr [eax + 8], ecx
            //   8b4dd8               | mov                 ecx, dword ptr [ebp - 0x28]
            //   89500c               | mov                 dword ptr [eax + 0xc], edx
            //   b801000000           | mov                 eax, 1

        $sequence_2 = { 8b4dd8 89500c b801000000 f745c000020000 8bd1 0f44f8 8bc1 }
            // n = 7, score = 100
            //   8b4dd8               | mov                 ecx, dword ptr [ebp - 0x28]
            //   89500c               | mov                 dword ptr [eax + 0xc], edx
            //   b801000000           | mov                 eax, 1
            //   f745c000020000       | test                dword ptr [ebp - 0x40], 0x200
            //   8bd1                 | mov                 edx, ecx
            //   0f44f8               | cmove               edi, eax
            //   8bc1                 | mov                 eax, ecx

        $sequence_3 = { 2bc1 3bd0 7425 8bfa 85ff 7e1f }
            // n = 6, score = 100
            //   2bc1                 | sub                 eax, ecx
            //   3bd0                 | cmp                 edx, eax
            //   7425                 | je                  0x27
            //   8bfa                 | mov                 edi, edx
            //   85ff                 | test                edi, edi
            //   7e1f                 | jle                 0x21

        $sequence_4 = { 1355bb 8cc6 4b 01c8 93 }
            // n = 5, score = 100
            //   1355bb               | adc                 edx, dword ptr [ebp - 0x45]
            //   8cc6                 | mov                 esi, es
            //   4b                   | dec                 ebx
            //   01c8                 | add                 eax, ecx
            //   93                   | xchg                eax, ebx

        $sequence_5 = { 8d81e8e7e7e7 3bc7 7ce6 833d????????00 0f85cc000000 6a00 }
            // n = 6, score = 100
            //   8d81e8e7e7e7         | lea                 eax, dword ptr [ecx - 0x18181818]
            //   3bc7                 | cmp                 eax, edi
            //   7ce6                 | jl                  0xffffffe8
            //   833d????????00       |                     
            //   0f85cc000000         | jne                 0xd2
            //   6a00                 | push                0

        $sequence_6 = { 8d45d8 2bca 50 51 68???????? }
            // n = 5, score = 100
            //   8d45d8               | lea                 eax, dword ptr [ebp - 0x28]
            //   2bca                 | sub                 ecx, edx
            //   50                   | push                eax
            //   51                   | push                ecx
            //   68????????           |                     

        $sequence_7 = { 8b75fc 894808 8b4dd8 89500c }
            // n = 4, score = 100
            //   8b75fc               | mov                 esi, dword ptr [ebp - 4]
            //   894808               | mov                 dword ptr [eax + 8], ecx
            //   8b4dd8               | mov                 ecx, dword ptr [ebp - 0x28]
            //   89500c               | mov                 dword ptr [eax + 0xc], edx

        $sequence_8 = { 2aba2191fab2 2125???????? 346d 2a91020a2292 b5fd a3???????? }
            // n = 6, score = 100
            //   2aba2191fab2         | sub                 bh, byte ptr [edx - 0x4d056edf]
            //   2125????????         |                     
            //   346d                 | xor                 al, 0x6d
            //   2a91020a2292         | sub                 dl, byte ptr [ecx - 0x6dddf5fe]
            //   b5fd                 | mov                 ch, 0xfd
            //   a3????????           |                     

        $sequence_9 = { 9c 4c 7c2c dc8cbc6c1ce9a9 7e92 c03cec9c 4c }
            // n = 7, score = 100
            //   9c                   | pushfd              
            //   4c                   | dec                 esp
            //   7c2c                 | jl                  0x2e
            //   dc8cbc6c1ce9a9       | fmul                qword ptr [esp + edi*4 - 0x5616e394]
            //   7e92                 | jle                 0xffffff94
            //   c03cec9c             | sar                 byte ptr [esp + ebp*8], 0x9c
            //   4c                   | dec                 esp

    condition:
        7 of them and filesize < 51014656
}