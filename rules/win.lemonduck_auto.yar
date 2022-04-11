rule win_lemonduck_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.lemonduck."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lemonduck"
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
        $sequence_0 = { eb13 8d48ff 488b4270 488b14c8 48895360 48895a58 488b5748 }
            // n = 7, score = 100
            //   eb13                 | je                  0xda
            //   8d48ff               | sub                 ecx, 1
            //   488b4270             | je                  0xd1
            //   488b14c8             | cmp                 ecx, 1
            //   48895360             | je                  0xc8
            //   48895a58             | dec                 eax
            //   488b5748             | lea                 eax, dword ptr [0x87392]

        $sequence_1 = { e8???????? 4863c8 48898e88000000 e9???????? 488b8e50010000 e8???????? 4863c8 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   4863c8               | jg                  0x275
            //   48898e88000000       | jne                 0x225
            //   e9????????           |                     
            //   488b8e50010000       | inc                 esp
            //   e8????????           |                     
            //   4863c8               | lea                 eax, dword ptr [ecx + 3]

        $sequence_2 = { 660f6fcc 66410fd4c8 4833f9 498bc9 4983f130 4883f120 4181e1f0ff1f00 }
            // n = 7, score = 100
            //   660f6fcc             | dec                 eax
            //   66410fd4c8           | mov                 ecx, 0xffffffff
            //   4833f9               | dec                 ecx
            //   498bc9               | mov                 eax, dword ptr [esi]
            //   4983f130             | dec                 ecx
            //   4883f120             | mov                 ecx, esi
            //   4181e1f0ff1f00       | call                dword ptr [eax + 8]

        $sequence_3 = { ffc7 4881c390000000 3bf8 7291 8b542448 41b8ffffffff 488b4c2450 }
            // n = 7, score = 100
            //   ffc7                 | movsx               ecx, word ptr [esp + 0x2e]
            //   4881c390000000       | mov                 edx, edi
            //   3bf8                 | inc                 esp
            //   7291                 | mov                 eax, ebx
            //   8b542448             | jmp                 0x7a0
            //   41b8ffffffff         | dec                 eax
            //   488b4c2450           | lea                 ecx, dword ptr [esp + 0x48]

        $sequence_4 = { f30f6f03 f30f6f4d97 660fef4587 f30f7f03 f30f6f4310 660fefc8 f30f7f4b10 }
            // n = 7, score = 100
            //   f30f6f03             | movzx               eax, dh
            //   f30f6f4d97           | inc                 eax
            //   660fef4587           | movzx               edx, ch
            //   f30f7f03             | dec                 eax
            //   f30f6f4310           | mov                 ecx, eax
            //   660fefc8             | nop                 
            //   f30f7f4b10           | mov                 dword ptr [esp + 0x20], edi

        $sequence_5 = { e8???????? 48b9000000000000ffff 4c23f1 4c0bf0 4c8975bf 8bf3 895dbb }
            // n = 7, score = 100
            //   e8????????           |                     
            //   48b9000000000000ffff     | inc    ebp
            //   4c23f1               | xor                 esi, esi
            //   4c0bf0               | nop                 word ptr [eax + eax]
            //   4c8975bf             | dec                 eax
            //   8bf3                 | mov                 edx, dword ptr [ebx + 0x10]
            //   895dbb               | dec                 eax

        $sequence_6 = { e8???????? 488bc8 488d15f4fc0500 498b04de 4889442438 896c2430 896c2428 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488bc8               | mov                 ecx, 0x18
            //   488d15f4fc0500       | movzx               edx, byte ptr [edx + 2]
            //   498b04de             | mov                 word ptr [esi + 0x18], cx
            //   4889442438           | mov                 ecx, eax
            //   896c2430             | and                 ecx, 3
            //   896c2428             | jge                 0x2e0

        $sequence_7 = { e9???????? 488b4c2428 ff15???????? 488d542420 c744242001010000 488d4c2430 ff15???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   488b4c2428           | xor                 ecx, esp
            //   ff15????????         |                     
            //   488d542420           | dec                 eax
            //   c744242001010000     | add                 esp, 0xd8
            //   488d4c2430           | cmp                 ecx, 1
            //   ff15????????         |                     

        $sequence_8 = { e8???????? e9???????? 488bcb c6433c01 e8???????? e9???????? 488b7b20 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   e9????????           |                     
            //   488bcb               | mov                 ebx, dword ptr [esp + 0x10]
            //   c6433c01             | ret                 
            //   e8????????           |                     
            //   e9????????           |                     
            //   488b7b20             | dec                 ecx

        $sequence_9 = { e8???????? 4889842498000000 c7400801000000 c7400c01000000 488d0d156c1300 488908 488d5010 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   4889842498000000     | dec                 ecx
            //   c7400801000000       | mov                 ecx, edx
            //   c7400c01000000       | dec                 esp
            //   488d0d156c1300       | mov                 edx, dword ptr [esp + 0x58]
            //   488908               | jbe                 0x37b
            //   488d5010             | dec                 eax

    condition:
        7 of them and filesize < 10011648
}