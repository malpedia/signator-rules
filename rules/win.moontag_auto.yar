rule win_moontag_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.moontag."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.moontag"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
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
        $sequence_0 = { 488d3d17430000 4885db 7407 44383b 480f45fb 488d45b0 }
            // n = 6, score = 100
            //   488d3d17430000       | inc                 ebp
            //   4885db               | xor                 eax, eax
            //   7407                 | dec                 eax
            //   44383b               | lea                 edx, [0x2f13]
            //   480f45fb             | dec                 eax
            //   488d45b0             | mov                 edi, dword ptr [ebp - 0x80]

        $sequence_1 = { f20f100d???????? 0f11442448 48895c2428 48896c2430 896c2440 89742444 f20f114c2458 }
            // n = 7, score = 100
            //   f20f100d????????     |                     
            //   0f11442448           | jmp                 0x973
            //   48895c2428           | mov                 byte ptr [edx + 1], al
            //   48896c2430           | add                 cl, 0xff
            //   896c2440             | jne                 0x961
            //   89742444             | dec                 eax
            //   f20f114c2458         | mov                 eax, dword ptr [esi]

        $sequence_2 = { 48894320 48894328 48894330 48894338 c7431802000000 48896c2430 4885ff }
            // n = 7, score = 100
            //   48894320             | je                  0x518
            //   48894328             | inc                 edx
            //   48894330             | cmp                 byte ptr [edx + eax], 0
            //   48894338             | jne                 0x4eb
            //   c7431802000000       | dec                 eax
            //   48896c2430           | lea                 ecx, [esp + 0x20]
            //   4885ff               | dec                 eax

        $sequence_3 = { c60322 eb2c c60362 eb27 c60366 eb22 c6036e }
            // n = 7, score = 100
            //   c60322               | dec                 eax
            //   eb2c                 | test                edi, edi
            //   c60362               | jne                 0xe44
            //   eb27                 | xor                 eax, eax
            //   c60366               | jmp                 0xea9
            //   eb22                 | inc                 ebp
            //   c6036e               | movsx               edi, byte ptr [ecx]

        $sequence_4 = { 33d2 448d4264 488d4d94 e8???????? c7459068000000 }
            // n = 5, score = 100
            //   33d2                 | dec                 esp
            //   448d4264             | mov                 edi, eax
            //   488d4d94             | dec                 eax
            //   e8????????           |                     
            //   c7459068000000       | mov                 dword ptr [esp + 0x20], ebx

        $sequence_5 = { 0f100d???????? 48894dc0 8d4b40 f20f1005???????? 66480f7ec8 488955c8 }
            // n = 6, score = 100
            //   0f100d????????       |                     
            //   48894dc0             | cmp                 ebx, 3
            //   8d4b40               | jne                 0x995
            //   f20f1005????????     |                     
            //   66480f7ec8           | mov                 ebx, eax
            //   488955c8             | dec                 eax

        $sequence_6 = { 48895de0 448bcb 48895de8 48895df0 }
            // n = 4, score = 100
            //   48895de0             | mov                 dword ptr [esp + 0x20], eax
            //   448bcb               | dec                 esp
            //   48895de8             | mov                 ecx, edx
            //   48895df0             | dec                 eax

        $sequence_7 = { 7354 498b0cff e8???????? 488bd8 4885c0 7420 }
            // n = 6, score = 100
            //   7354                 | mov                 ebx, eax
            //   498b0cff             | dec                 eax
            //   e8????????           |                     
            //   488bd8               | test                eax, eax
            //   4885c0               | je                  0x4d
            //   7420                 | dec                 ebp

        $sequence_8 = { 0fb744244a 3bc1 7f13 0f8c68010000 0fb744244c }
            // n = 5, score = 100
            //   0fb744244a           | mov                 ecx, edi
            //   3bc1                 | dec                 eax
            //   7f13                 | mov                 dword ptr [ebx + 0x38], eax
            //   0f8c68010000         | dec                 eax
            //   0fb744244c           | mov                 edx, ebx

        $sequence_9 = { 4885db 0f8487000000 488d4580 4883fe10 480f43c7 4883fb01 7518 }
            // n = 7, score = 100
            //   4885db               | sub                 al, 0x30
            //   0f8487000000         | cmp                 al, 9
            //   488d4580             | ja                  0x634
            //   4883fe10             | dec                 eax
            //   480f43c7             | mov                 dword ptr [esp + 0xa0], esi
            //   4883fb01             | xor                 esi, esi
            //   7518                 | cmp                 al, 0x5c

    condition:
        7 of them and filesize < 140288
}