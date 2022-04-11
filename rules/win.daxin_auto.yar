rule win_daxin_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.daxin."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.daxin"
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
        $sequence_0 = { 2bc2 d1f8 99 f7f9 }
            // n = 4, score = 400
            //   2bc2                 | sub                 eax, edx
            //   d1f8                 | sar                 eax, 1
            //   99                   | cdq                 
            //   f7f9                 | idiv                ecx

        $sequence_1 = { 4c8d442470 488d8c24d8010000 ba00000080 c744242880000000 488364242000 c744247030000000 c784248800000040020000 }
            // n = 7, score = 300
            //   4c8d442470           | dec                 eax
            //   488d8c24d8010000     | mov                 esi, ecx
            //   ba00000080           | shl                 edx, 0x10
            //   c744242880000000     | inc                 cx
            //   488364242000         | rol                 ebx, 8
            //   c744247030000000     | inc                 ecx
            //   c784248800000040020000     | movzx    eax, bx

        $sequence_2 = { 57 4154 4883ec20 33ff 488bea 488bf1 }
            // n = 6, score = 300
            //   57                   | dec                 eax
            //   4154                 | mov                 ecx, dword ptr [esp + 0x70]
            //   4883ec20             | push                edi
            //   33ff                 | inc                 ecx
            //   488bea               | push                esp
            //   488bf1               | dec                 eax

        $sequence_3 = { 4c8bcf 48896c2428 21542420 ff15???????? 4c8bd8 }
            // n = 5, score = 300
            //   4c8bcf               | or                  edx, eax
            //   48896c2428           | dec                 esp
            //   21542420             | lea                 eax, dword ptr [esp + 0x70]
            //   ff15????????         |                     
            //   4c8bd8               | dec                 eax

        $sequence_4 = { e8???????? 4c8bd8 b81f85eb51 442b9ed8000000 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   4c8bd8               | mov                 ebx, eax
            //   b81f85eb51           | dec                 ecx
            //   442b9ed8000000       | cmp                 eax, esp

        $sequence_5 = { c1e210 6641c1c308 410fb7c3 0bd0 }
            // n = 4, score = 300
            //   c1e210               | sub                 esp, 0x20
            //   6641c1c308           | xor                 edi, edi
            //   410fb7c3             | dec                 eax
            //   0bd0                 | mov                 ebp, edx

        $sequence_6 = { e8???????? 4c8bd8 493bc4 0f84df000000 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   4c8bd8               | mov                 dword ptr [esp + 0x70], 0x30
            //   493bc4               | mov                 dword ptr [esp + 0x88], 0x240
            //   0f84df000000         | dec                 esp

        $sequence_7 = { 4c8d40c8 baffff1f00 c740c830000000 ff15???????? 85c0 7826 488b4c2470 }
            // n = 7, score = 300
            //   4c8d40c8             | dec                 esp
            //   baffff1f00           | lea                 eax, dword ptr [eax - 0x38]
            //   c740c830000000       | mov                 edx, 0x1fffff
            //   ff15????????         |                     
            //   85c0                 | mov                 dword ptr [eax - 0x38], 0x30
            //   7826                 | test                eax, eax
            //   488b4c2470           | js                  0x28

        $sequence_8 = { 88450d 8b4f0c 8b5678 8d4640 03d1 }
            // n = 5, score = 100
            //   88450d               | dec                 eax
            //   8b4f0c               | test                eax, eax
            //   8b5678               | jne                 0xd
            //   8d4640               | dec                 esp
            //   03d1                 | mov                 ebx, eax

        $sequence_9 = { 884604 8b4608 50 51 }
            // n = 4, score = 100
            //   884604               | je                  0xc
            //   8b4608               | mov                 ecx, eax
            //   50                   | mov                 eax, dword ptr [ecx]
            //   51                   | test                eax, eax

        $sequence_10 = { 884604 85ed 0f8436010000 8b4d18 }
            // n = 4, score = 100
            //   884604               | cdq                 
            //   85ed                 | idiv                ecx
            //   0f8436010000         | cdq                 
            //   8b4d18               | sub                 eax, edx

        $sequence_11 = { 884604 8b01 85c0 7408 }
            // n = 4, score = 100
            //   884604               | add                 edx, ecx
            //   8b01                 | push                eax
            //   85c0                 | mov                 dword ptr [esi + 0x78], edx
            //   7408                 | mov                 byte ptr [esi + 4], al

        $sequence_12 = { 884604 85db 0f8438010000 8b4b18 }
            // n = 4, score = 100
            //   884604               | inc                 esp
            //   85db                 | sub                 ebx, dword ptr [esi + 0xd8]
            //   0f8438010000         | inc                 ecx
            //   8b4b18               | mul                 ebx

        $sequence_13 = { 884604 8b03 8d542410 51 }
            // n = 4, score = 100
            //   884604               | test                ecx, ecx
            //   8b03                 | je                  0x140
            //   8d542410             | mov                 eax, dword ptr [esp + 0x20]
            //   51                   | mov                 byte ptr [esi + 4], al

        $sequence_14 = { 884604 8b3b 8b4304 8a5604 }
            // n = 4, score = 100
            //   884604               | test                ecx, ecx
            //   8b3b                 | je                  0x131
            //   8b4304               | mov                 edx, dword ptr [esp + 0x1c]
            //   8a5604               | mov                 byte ptr [esi + 4], al

    condition:
        7 of them and filesize < 3475456
}