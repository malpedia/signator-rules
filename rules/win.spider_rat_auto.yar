rule win_spider_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.spider_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.spider_rat"
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
        $sequence_0 = { 488bd9 e8???????? 488bcb 488907 4885c0 7409 e8???????? }
            // n = 7, score = 200
            //   488bd9               | jmp                 0x5de
            //   e8????????           |                     
            //   488bcb               | or                  dword ptr [eax + 0x10], 0xffffffff
            //   488907               | dec                 eax
            //   4885c0               | mov                 eax, dword ptr [ecx + 0x10]
            //   7409                 | mov                 dword ptr [eax + 8], ebp
            //   e8????????           |                     

        $sequence_1 = { 7505 e8???????? 48837b2010 7206 488b4b08 eb04 488d4b08 }
            // n = 7, score = 200
            //   7505                 | je                  0x2ae
            //   e8????????           |                     
            //   48837b2010           | dec                 eax
            //   7206                 | mov                 ecx, dword ptr [ecx]
            //   488b4b08             | dec                 eax
            //   eb04                 | mov                 eax, dword ptr [ecx]
            //   488d4b08             | dec                 eax

        $sequence_2 = { 83e801 7466 83e801 745a 83f801 756f 488bbed8000000 }
            // n = 7, score = 200
            //   83e801               | dec                 esp
            //   7466                 | lea                 ebx, dword ptr [esp + 0x60]
            //   83e801               | dec                 ecx
            //   745a                 | mov                 ebx, dword ptr [ebx + 0x20]
            //   83f801               | dec                 ecx
            //   756f                 | mov                 ebp, dword ptr [ebx + 0x28]
            //   488bbed8000000       | dec                 ecx

        $sequence_3 = { 448960e8 ff15???????? 488b4f10 4885c9 741a 448b4c2460 448bc6 }
            // n = 7, score = 200
            //   448960e8             | lea                 ecx, dword ptr [0x2a879]
            //   ff15????????         |                     
            //   488b4f10             | dec                 eax
            //   4885c9               | mov                 dword ptr [esi], eax
            //   741a                 | xor                 ebx, ebx
            //   448b4c2460           | dec                 eax
            //   448bc6               | mov                 ecx, dword ptr [esp + 0x50]

        $sequence_4 = { 33ff 488bea 488bf1 483bd7 7d06 e8???????? cc }
            // n = 7, score = 200
            //   33ff                 | mov                 ecx, edi
            //   488bea               | dec                 eax
            //   488bf1               | lea                 esi, dword ptr [0x65903]
            //   483bd7               | dec                 eax
            //   7d06                 | arpl                ax, bx
            //   e8????????           |                     
            //   cc                   | dec                 eax

        $sequence_5 = { 488d4c2478 458bcc 4533c0 ff15???????? 413bc7 8bd8 0f8c46020000 }
            // n = 7, score = 200
            //   488d4c2478           | dec                 eax
            //   458bcc               | lea                 ecx, dword ptr [0xfffb8372]
            //   4533c0               | dec                 eax
            //   ff15????????         |                     
            //   413bc7               | add                 eax, ecx
            //   8bd8                 | dec                 eax
            //   0f8c46020000         | mov                 dword ptr [esp + 0x48], eax

        $sequence_6 = { 488bea 48c745400f000000 48c7453800000000 c6452800 41b81c000000 488d15d2d00000 488d4d20 }
            // n = 7, score = 200
            //   488bea               | dec                 eax
            //   48c745400f000000     | test                ecx, ecx
            //   48c7453800000000     | je                  0x136f
            //   c6452800             | and                 dword ptr [ecx + 0x138], 0
            //   41b81c000000         | dec                 eax
            //   488d15d2d00000       | mov                 esi, ecx
            //   488d4d20             | mov                 dword ptr [eax + 0x18], 4

        $sequence_7 = { ba0b010000 b801000000 3bca 0f8791020000 7450 83f93e 0f8735010000 }
            // n = 7, score = 200
            //   ba0b010000           | dec                 ecx
            //   b801000000           | mov                 eax, dword ptr [esp + 0x40]
            //   3bca                 | dec                 eax
            //   0f8791020000         | cmp                 dword ptr [ecx + edx + 0x20], eax
            //   7450                 | inc                 ecx
            //   83f93e               | mov                 byte ptr [ebp], cl
            //   0f8735010000         | dec                 ebx

        $sequence_8 = { 488bc2 48c1e83f 4803d0 7505 488bfe eb3c 483bf9 }
            // n = 7, score = 200
            //   488bc2               | inc                 eax
            //   48c1e83f             | xor                 dh, dh
            //   4803d0               | inc                 eax
            //   7505                 | test                al, ch
            //   488bfe               | je                  0x1b8
            //   eb3c                 | jne                 0x1ae
            //   483bf9               | inc                 eax

        $sequence_9 = { 740d 4183e5fd 488bcb ff15???????? 4084ed 0f85da000000 488b8c24a8000000 }
            // n = 7, score = 200
            //   740d                 | call                dword ptr [eax + 0x10]
            //   4183e5fd             | mov                 ecx, 0x28
            //   488bcb               | dec                 eax
            //   ff15????????         |                     
            //   4084ed               | mov                 esi, eax
            //   0f85da000000         | dec                 eax
            //   488b8c24a8000000     | mov                 dword ptr [esp + 0x38], eax

    condition:
        7 of them and filesize < 1107968
}