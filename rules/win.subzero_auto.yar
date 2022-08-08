rule win_subzero_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-08-05"
        version = "1"
        description = "Detects win.subzero."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.subzero"
        malpedia_rule_date = "20220805"
        malpedia_hash = "6ec06c64bcfdbeda64eff021c766b4ce34542b71"
        malpedia_version = "20220808"
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
        $sequence_0 = { c744242005000000 895c247c 48c744246804000000 48c744245808000000 e8???????? 488b8c2480000000 4833cc }
            // n = 7, score = 100
            //   c744242005000000     | dec                 ecx
            //   895c247c             | mov                 edx, edi
            //   48c744246804000000     | dec    eax
            //   48c744245808000000     | sub    edx, ebx
            //   e8????????           |                     
            //   488b8c2480000000     | dec                 eax
            //   4833cc               | sar                 edx, 4

        $sequence_1 = { e8???????? 33d2 85c0 0f88c576feff e9???????? 448bc8 4c8bc6 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   33d2                 | mov                 eax, dword ptr [esi + 0x10]
            //   85c0                 | dec                 ebx
            //   0f88c576feff         | lea                 ecx, [edi]
            //   e9????????           |                     
            //   448bc8               | dec                 eax
            //   4c8bc6               | add                 ebx, 0xc

        $sequence_2 = { e8???????? 41b888130000 488d5640 488bcf e8???????? 4885db 740f }
            // n = 7, score = 100
            //   e8????????           |                     
            //   41b888130000         | dec                 eax
            //   488d5640             | add                 edi, 0x10
            //   488bcf               | dec                 eax
            //   e8????????           |                     
            //   4885db               | cmp                 edi, esi
            //   740f                 | jne                 7

        $sequence_3 = { ff15???????? 396b20 0f85a44f0100 488b9c2408010000 4881c4d0000000 5f 5e }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   396b20               | lea                 ecx, [ebx + 0x10]
            //   0f85a44f0100         | dec                 eax
            //   488b9c2408010000     | mov                 dword ptr [edx + 8], eax
            //   4881c4d0000000       | dec                 ecx
            //   5f                   | and                 dword ptr [eax], 0
            //   5e                   | dec                 esp

        $sequence_4 = { e8???????? 89bbd4000000 85c0 7911 488b5c2430 488b742438 4883c420 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   89bbd4000000         | mov                 dword ptr [eax - 0x10], 1
            //   85c0                 | dec                 esp
            //   7911                 | lea                 ecx, [eax + 0x18]
            //   488b5c2430           | dec                 esp
            //   488b742438           | mov                 dword ptr [eax - 0x18], eax
            //   4883c420             | dec                 eax

        $sequence_5 = { 4c8d4320 488bcf 488d15e40a0500 488bc5 ff15???????? 488b7c2460 488b6c2458 }
            // n = 7, score = 100
            //   4c8d4320             | mov                 edx, eax
            //   488bcf               | test                eax, eax
            //   488d15e40a0500       | jle                 0x27f
            //   488bc5               | movzx               edx, dx
            //   ff15????????         |                     
            //   488b7c2460           | or                  edx, 0x80070000
            //   488b6c2458           | mov                 eax, dword ptr [esp + 0x50]

        $sequence_6 = { 448bc8 4c8d055a700300 ba99000000 e8???????? eb37 4c8d442450 488b542458 }
            // n = 7, score = 100
            //   448bc8               | mov                 ecx, dword ptr [ebx - 0x70]
            //   4c8d055a700300       | dec                 eax
            //   ba99000000           | test                ecx, ecx
            //   e8????????           |                     
            //   eb37                 | dec                 ecx
            //   4c8d442450           | mov                 ecx, esi
            //   488b542458           | dec                 ecx

        $sequence_7 = { 833902 0f865e010000 48ba0000000000400000 e8???????? 84c0 0f8447010000 488b4328 }
            // n = 7, score = 100
            //   833902               | mov                 edi, dword ptr [ebp + 0x60]
            //   0f865e010000         | dec                 ebp
            //   48ba0000000000400000     | mov    ebp, ecx
            //   e8????????           |                     
            //   84c0                 | inc                 ecx
            //   0f8447010000         | push                ebp
            //   488b4328             | inc                 ecx

        $sequence_8 = { e8???????? 85c0 7523 488d153dc10200 e8???????? 85c0 740c }
            // n = 7, score = 100
            //   e8????????           |                     
            //   85c0                 | mov                 dword ptr [esp + 0x20], 0xfffffffe
            //   7523                 | dec                 eax
            //   488d153dc10200       | mov                 dword ptr [esp + 0x50], ebx
            //   e8????????           |                     
            //   85c0                 | dec                 eax
            //   740c                 | mov                 dword ptr [esp + 0x58], esi

        $sequence_9 = { c1e808 8d0c80 418bc7 c1e810 0fb6c0 03c8 410fb6c7 }
            // n = 7, score = 100
            //   c1e808               | add                 byte ptr [eax + 0x24648348], al
            //   8d0c80               | inc                 eax
            //   418bc7               | add                 byte ptr [ebx + 0xfc085d8], cl
            //   c1e810               | mov                 dl, ch
            //   0fb6c0               | add                 byte ptr [eax], al
            //   03c8                 | add                 byte ptr [ebx + 0x1588d], al
            //   410fb6c7             | add                 byte ptr [ecx], al

    condition:
        7 of them and filesize < 1420288
}