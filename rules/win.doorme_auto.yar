rule win_doorme_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.doorme."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.doorme"
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
        $sequence_0 = { 7515 488d050d870200 4a8b04e8 385c0739 0f84c9000000 488d05f8860200 }
            // n = 6, score = 100
            //   7515                 | dec                 eax
            //   488d050d870200       | mov                 ecx, ebp
            //   4a8b04e8             | dec                 eax
            //   385c0739             | cmp                 ebp, edx
            //   0f84c9000000         | jae                 0xd32
            //   488d05f8860200       | movzx               eax, byte ptr [ecx]

        $sequence_1 = { 488d8c24c4000000 e8???????? 90 488b2d???????? 488b35???????? 4885f6 7543 }
            // n = 7, score = 100
            //   488d8c24c4000000     | dec                 eax
            //   e8????????           |                     
            //   90                   | mov                 eax, ecx
            //   488b2d????????       |                     
            //   488b35????????       |                     
            //   4885f6               | and                 ecx, 0x3f
            //   7543                 | dec                 eax

        $sequence_2 = { 49ffc0 42803c0700 75f6 488bd7 488d4d68 e8???????? 90 }
            // n = 7, score = 100
            //   49ffc0               | lea                 edx, dword ptr [ebp + 0x58]
            //   42803c0700           | dec                 eax
            //   75f6                 | cmp                 dword ptr [ebp + 0x70], 0x10
            //   488bd7               | dec                 eax
            //   488d4d68             | cmovae              edx, dword ptr [ebp + 0x58]
            //   e8????????           |                     
            //   90                   | dec                 eax

        $sequence_3 = { 488d41f8 4883f81f 7751 498bc8 e8???????? 4d896e10 49c746180f000000 }
            // n = 7, score = 100
            //   488d41f8             | dec                 eax
            //   4883f81f             | add                 edx, 0x27
            //   7751                 | dec                 esp
            //   498bc8               | mov                 eax, dword ptr [ecx - 8]
            //   e8????????           |                     
            //   4d896e10             | dec                 ecx
            //   49c746180f000000     | sub                 ecx, eax

        $sequence_4 = { 7404 f0440108 488d4138 41b806000000 488d15dde60100 483950f0 740c }
            // n = 7, score = 100
            //   7404                 | je                  0xb5
            //   f0440108             | dec                 eax
            //   488d4138             | lea                 edx, dword ptr [0xe28d]
            //   41b806000000         | dec                 eax
            //   488d15dde60100       | mov                 ecx, ebx
            //   483950f0             | dec                 eax
            //   740c                 | lea                 edx, dword ptr [0x12291]

        $sequence_5 = { e8???????? 4c8d9c24d0000000 498b5b20 498b7330 498be3 415e 5f }
            // n = 7, score = 100
            //   e8????????           |                     
            //   4c8d9c24d0000000     | mov                 eax, dword ptr [esi]
            //   498b5b20             | inc                 esp
            //   498b7330             | mov                 byte ptr [eax + ecx], cl
            //   498be3               | inc                 esp
            //   415e                 | mov                 byte ptr [eax + ecx + 1], dh
            //   5f                   | jmp                 0x651

        $sequence_6 = { 4883c0f8 4883f81f 0f8735010000 e8???????? 660f6f05???????? f30f7f4527 }
            // n = 6, score = 100
            //   4883c0f8             | add                 edx, ecx
            //   4883f81f             | rol                 edx, 7
            //   0f8735010000         | inc                 ecx
            //   e8????????           |                     
            //   660f6f05????????     |                     
            //   f30f7f4527           | and                 eax, ebx

        $sequence_7 = { 884658 48396e48 7511 8b5610 83ca04 4533c0 488bce }
            // n = 7, score = 100
            //   884658               | jmp                 0x500
            //   48396e48             | dec                 eax
            //   7511                 | lea                 ecx, dword ptr [ebp - 0x58]
            //   8b5610               | test                al, al
            //   83ca04               | dec                 ecx
            //   4533c0               | cmove               ebx, ebp
            //   488bce               | dec                 eax

        $sequence_8 = { eb0c 83f901 750d 488d0d09d90200 e8???????? 90 }
            // n = 6, score = 100
            //   eb0c                 | mov                 al, byte ptr [ebx]
            //   83f901               | dec                 ecx
            //   750d                 | add                 ebx, ecx
            //   488d0d09d90200       | dec                 ecx
            //   e8????????           |                     
            //   90                   | mov                 ecx, dword ptr [esp + esi*8 + 0x41280]

        $sequence_9 = { 41b16f 41b263 4533db 3406 884561 80f106 }
            // n = 6, score = 100
            //   41b16f               | lea                 eax, dword ptr [ebp + 0x68]
            //   41b263               | dec                 eax
            //   4533db               | cmp                 edi, 0x10
            //   3406                 | dec                 eax
            //   884561               | cmovae              eax, ebx
            //   80f106               | dec                 ecx

    condition:
        7 of them and filesize < 580608
}