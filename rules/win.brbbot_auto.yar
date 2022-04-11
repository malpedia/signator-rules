rule win_brbbot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.brbbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.brbbot"
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
        $sequence_0 = { 7409 498bcc ff15???????? 488b4c2440 4c8b6c2450 }
            // n = 5, score = 100
            //   7409                 | dec                 eax
            //   498bcc               | sar                 eax, 5
            //   ff15????????         |                     
            //   488b4c2440           | dec                 eax
            //   4c8b6c2450           | arpl                dx, cx

        $sequence_1 = { 448bc5 488bd6 488bc8 48895c2420 }
            // n = 4, score = 100
            //   448bc5               | inc                 ebp
            //   488bd6               | xor                 esp, esp
            //   488bc8               | dec                 ebp
            //   48895c2420           | mov                 esi, eax

        $sequence_2 = { 458bfc ff15???????? 488d1532cc0000 488bc8 ff15???????? 4c8be8 4885c0 }
            // n = 7, score = 100
            //   458bfc               | lea                 eax, dword ptr [0xc28e]
            //   ff15????????         |                     
            //   488d1532cc0000       | dec                 edx
            //   488bc8               | mov                 edx, dword ptr [eax]
            //   ff15????????         |                     
            //   4c8be8               | inc                 ecx
            //   4885c0               | cmp                 dword ptr [edi + edx + 0x50], 0

        $sequence_3 = { 895c2428 4889bc2440030000 c744242002000000 ff15???????? 488bf8 }
            // n = 5, score = 100
            //   895c2428             | dec                 eax
            //   4889bc2440030000     | mov                 dword ptr [esp + 0x20], eax
            //   c744242002000000     | jmp                 0x3d6
            //   ff15????????         |                     
            //   488bf8               | dec                 eax

        $sequence_4 = { 486bc958 48030cc2 eb07 488d0d98d00000 f6410820 }
            // n = 5, score = 100
            //   486bc958             | mov                 edx, edi
            //   48030cc2             | test                eax, eax
            //   eb07                 | jne                 0x529
            //   488d0d98d00000       | dec                 eax
            //   f6410820             | lea                 ecx, dword ptr [0x109b]

        $sequence_5 = { 488b8b50010000 482bcf e8???????? 488b8b30010000 e8???????? 488b8b58010000 488d05ccb50000 }
            // n = 7, score = 100
            //   488b8b50010000       | mov                 eax, ecx
            //   482bcf               | dec                 ecx
            //   e8????????           |                     
            //   488b8b30010000       | mov                 ecx, ebp
            //   e8????????           |                     
            //   488b8b58010000       | dec                 ebp
            //   488d05ccb50000       | mov                 eax, ebp

        $sequence_6 = { 7419 880a 4b8b84f9c05a0100 48ffc2 458d60f9 4103da 448844303a }
            // n = 7, score = 100
            //   7419                 | not                 ecx
            //   880a                 | dec                 eax
            //   4b8b84f9c05a0100     | lea                 edi, dword ptr [edx + ecx + 3]
            //   48ffc2               | inc                 ecx
            //   458d60f9             | lea                 edx, dword ptr [ebp + 7]
            //   4103da               | dec                 eax
            //   448844303a           | mov                 ecx, eax

        $sequence_7 = { 488d542440 488d0d77db0000 41b804010000 4c8be0 ff15???????? 85c0 0f84c3010000 }
            // n = 7, score = 100
            //   488d542440           | lea                 ecx, dword ptr [0xd328]
            //   488d0d77db0000       | mov                 edx, 0xfa0
            //   41b804010000         | dec                 eax
            //   4c8be0               | mov                 eax, ebp
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f84c3010000         | je                  0x227

        $sequence_8 = { 488bcd e8???????? 4885c0 7403 448820 ba20000000 }
            // n = 6, score = 100
            //   488bcd               | dec                 eax
            //   e8????????           |                     
            //   4885c0               | mov                 eax, ecx
            //   7403                 | and                 ecx, 0x1f
            //   448820               | jae                 0x1045
            //   ba20000000           | mov                 al, byte ptr [ebx]

        $sequence_9 = { 895c2420 488bfb ff15???????? 85c0 749d 33d2 488d8c24e0000000 }
            // n = 7, score = 100
            //   895c2420             | mov                 ecx, esi
            //   488bfb               | dec                 esp
            //   ff15????????         |                     
            //   85c0                 | mov                 esi, dword ptr [ebp - 0x30]
            //   749d                 | js                  0x5e8
            //   33d2                 | mov                 eax, ebx
            //   488d8c24e0000000     | dec                 eax

    condition:
        7 of them and filesize < 198656
}