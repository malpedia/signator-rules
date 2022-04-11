rule win_nightsky_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.nightsky."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nightsky"
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
        $sequence_0 = { ffca 0fca 81ea73359678 f9 f8 c1ca03 f5 }
            // n = 7, score = 100
            //   ffca                 | mov                 dword ptr [esp + 0x10], esi
            //   0fca                 | dec                 eax
            //   81ea73359678         | mov                 dword ptr [esp + 0x18], edi
            //   f9                   | inc                 ecx
            //   f8                   | push                esi
            //   c1ca03               | dec                 eax
            //   f5                   | sub                 esp, 0x20

        $sequence_1 = { 48895c2438 e9???????? 483bdd 7564 4885ed 7507 bd01000000 }
            // n = 7, score = 100
            //   48895c2438           | inc                 edx
            //   e9????????           |                     
            //   483bdd               | movzx               eax, byte ptr [eax + esi + 0x56310]
            //   7564                 | inc                 esp
            //   4885ed               | xor                 ecx, eax
            //   7507                 | mov                 eax, esi
            //   bd01000000           | inc                 edx

        $sequence_2 = { 460fb68c3110630500 897d48 420fb6843010630500 c1e008 4433c8 418bc2 }
            // n = 6, score = 100
            //   460fb68c3110630500     | inc    esp
            //   897d48               | or                  ebx, ecx
            //   420fb6843010630500     | inc    ecx
            //   c1e008               | movzx               ecx, al
            //   4433c8               | inc                 ecx
            //   418bc2               | shl                 ebx, 8

        $sequence_3 = { 81ef4722942f 664181fc1c33 413af1 53 }
            // n = 4, score = 100
            //   81ef4722942f         | inc                 sp
            //   664181fc1c33         | xadd                ebp, eax
            //   413af1               | dec                 eax
            //   53                   | sub                 esp, 0x180

        $sequence_4 = { 438d3c64 4863c7 893d???????? 488d1cc540000000 0f1f4000 488b0d???????? 4c8bc3 }
            // n = 7, score = 100
            //   438d3c64             | cmc                 
            //   4863c7               | xor                 dword ptr [esp], esi
            //   893d????????         |                     
            //   488d1cc540000000     | inc                 ecx
            //   0f1f4000             | inc                 ecx
            //   488b0d????????       |                     
            //   4c8bc3               | inc                 ecx

        $sequence_5 = { 488d3de9100400 660f1f840000000000 488b17 488d4c245c ff15???????? 85c0 743f }
            // n = 7, score = 100
            //   488d3de9100400       | sub                 esp, 0x88
            //   660f1f840000000000     | dec    eax
            //   488b17               | lea                 ecx, dword ptr [0x113d1]
            //   488d4c245c           | dec                 esp
            //   ff15????????         |                     
            //   85c0                 | mov                 dword ptr [esp + 0x58], ebx
            //   743f                 | inc                 ebp

        $sequence_6 = { 498bde 4533ff 4983cdff 90 4c8b27 4c03e5 4c3be3 }
            // n = 7, score = 100
            //   498bde               | and                 ch, ch
            //   4533ff               | dec                 eax
            //   4983cdff             | lea                 eax, dword ptr [eax + esi]
            //   90                   | dec                 eax
            //   4c8b27               | mov                 ebx, eax
            //   4c03e5               | add                 cl, 0x4d
            //   4c3be3               | inc                 sp

        $sequence_7 = { 48895c2460 488bcb 41ffd4 ebe7 c744242001000000 4883c438 }
            // n = 6, score = 100
            //   48895c2460           | push                edi
            //   488bcb               | dec                 eax
            //   41ffd4               | sub                 esp, 0x70
            //   ebe7                 | dec                 eax
            //   c744242001000000     | xor                 eax, esp
            //   4883c438             | dec                 eax

        $sequence_8 = { 4c8d0db0e70000 b904000000 4c8d059ce70000 488d159de70000 e8???????? 488bd8 4885c0 }
            // n = 7, score = 100
            //   4c8d0db0e70000       | mov                 ecx, ebx
            //   b904000000           | dec                 eax
            //   4c8d059ce70000       | lea                 ecx, dword ptr [0x543f2]
            //   488d159de70000       | dec                 eax
            //   e8????????           |                     
            //   488bd8               | mov                 ebx, dword ptr [eax + edx*8]
            //   4885c0               | lea                 eax, dword ptr [edx + 1]

        $sequence_9 = { 48c7442420feffffff 488d15bde20000 488d4c2428 e8???????? 90 488d4c2450 e8???????? }
            // n = 7, score = 100
            //   48c7442420feffffff     | mov    dword ptr [esp + 0x190], ecx
            //   488d15bde20000       | dec                 eax
            //   488d4c2428           | mov                 eax, dword ptr [esp + 0x40]
            //   e8????????           |                     
            //   90                   | dec                 ebp
            //   488d4c2450           | lea                 edi, dword ptr [esi + eax]
            //   e8????????           |                     

    condition:
        7 of them and filesize < 19536896
}