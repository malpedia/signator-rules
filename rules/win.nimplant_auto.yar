rule win_nimplant_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.nimplant."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nimplant"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
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
        $sequence_0 = { 4c89e9 0f11642440 e8???????? 803b00 0f8515ffffff 488b4c2468 4885c9 }
            // n = 7, score = 100
            //   4c89e9               | add                 edx, edx
            //   0f11642440           | dec                 eax
            //   e8????????           |                     
            //   803b00               | add                 eax, 3
            //   0f8515ffffff         | dec                 eax
            //   488b4c2468           | cmp                 ecx, edx
            //   4885c9               | dec                 esp

        $sequence_1 = { 894c2430 4889ac24b0000000 e9???????? 4981ffff7f0000 4c89f2 488b4b08 490f4ed7 }
            // n = 7, score = 100
            //   894c2430             | dec                 eax
            //   4889ac24b0000000     | lea                 eax, [0x589ec]
            //   e9????????           |                     
            //   4981ffff7f0000       | dec                 eax
            //   4c89f2               | mov                 dword ptr [ecx + 0x18], 0x24
            //   488b4b08             | dec                 eax
            //   490f4ed7             | mov                 dword ptr [ecx + 0x20], eax

        $sequence_2 = { 488d051e3a0800 48895110 48894120 48c741183a000000 48c7410800000000 48c7442420a1060000 e8???????? }
            // n = 7, score = 100
            //   488d051e3a0800       | test                ebp, ebp
            //   48895110             | jne                 0xfc6
            //   48894120             | inc                 ecx
            //   48c741183a000000     | mov                 eax, 0x4909bf2b
            //   48c7410800000000     | dec                 esp
            //   48c7442420a1060000     | mov    edx, ebp
            //   e8????????           |                     

        $sequence_3 = { e8???????? 488b442440 488b542448 44886c0208 4883c001 0f8093040000 488b542448 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488b442440           | sub                 esp, 0x1d8
            //   488b542448           | inc                 ecx
            //   44886c0208           | mov                 eax, 0x7f2bfd03
            //   4883c001             | push                ebp
            //   0f8093040000         | push                edi
            //   488b542448           | push                esi

        $sequence_4 = { e8???????? 4c8b442430 48ba0000000000000040 4889f1 4c01e9 0f80b1000000 4885c9 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   4c8b442430           | por                 mm2, mm4
            //   48ba0000000000000040     | por    xmm3, xmm2
            //   4889f1               | inc                 ecx
            //   4c01e9               | movq                mm2, mm5
            //   0f80b1000000         | inc                 esp
            //   4885c9               | movq                mm4, mm3

        $sequence_5 = { f30f6f25???????? 4889ea 41b8a94d975e 4c89e9 4c899c2408010000 4c89942400010000 0f11a42410010000 }
            // n = 7, score = 100
            //   f30f6f25????????     |                     
            //   4889ea               | mov                 edx, dword ptr [esp + 0x40]
            //   41b8a94d975e         | dec                 eax
            //   4c89e9               | mov                 eax, dword ptr [esp + 0x48]
            //   4c899c2408010000     | dec                 eax
            //   4c89942400010000     | test                edx, edx
            //   0f11a42410010000     | dec                 eax

        $sequence_6 = { 488b9424f0000000 4889d1 4883e904 0f80de0f0000 4839ca 0f8e58100000 4885c9 }
            // n = 7, score = 100
            //   488b9424f0000000     | add                 byte ptr [eax + 0x48], al
            //   4889d1               | test                dword ptr [ecx], eax
            //   4883e904             | je                  0x350
            //   0f80de0f0000         | dec                 eax
            //   4839ca               | mov                 ecx, dword ptr [esp + 0x98]
            //   0f8e58100000         | dec                 eax
            //   4885c9               | test                ecx, ecx

        $sequence_7 = { e8???????? 803b00 488b942488000000 488b842480000000 0f8599feffff 4c8b4e58 4c89f1 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   803b00               | dec                 esp
            //   488b942488000000     | mov                 ecx, esp
            //   488b842480000000     | je                  0x1a7
            //   0f8599feffff         | dec                 eax
            //   4c8b4e58             | test                dword ptr [ebp], edi
            //   4c89f1               | je                  0x4ca

        $sequence_8 = { 80f90b 0f873b1a0000 0fb6f2 83ee01 4863f6 4883c60c 48c1e604 }
            // n = 7, score = 100
            //   80f90b               | mov                 edx, esi
            //   0f873b1a0000         | dec                 esp
            //   0fb6f2               | mov                 eax, dword ptr [esp + 0x78]
            //   83ee01               | mov                 edx, 1
            //   4863f6               | dec                 eax
            //   4883c60c             | mov                 eax, dword ptr [ecx]
            //   48c1e604             | call                dword ptr [eax + 0x18]

        $sequence_9 = { 4889eb 48897c2440 488b7c2438 4889c5 4c89ee 4c897c2460 }
            // n = 6, score = 100
            //   4889eb               | mov                 ecx, eax
            //   48897c2440           | movzx               esi, byte ptr [ebx]
            //   488b7c2438           | dec                 eax
            //   4889c5               | mov                 dword ptr [esp + 0x78], eax
            //   4c89ee               | inc                 eax
            //   4c897c2460           | test                dh, dh

    condition:
        7 of them and filesize < 1811456
}