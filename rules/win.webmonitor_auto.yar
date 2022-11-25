rule win_webmonitor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.webmonitor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webmonitor"
        malpedia_rule_date = "20221118"
        malpedia_hash = "e0702e2e6d1d00da65c8a29a4ebacd0a4c59e1af"
        malpedia_version = "20221125"
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
        $sequence_0 = { a4 44 43 00dc 7442 000477 }
            // n = 6, score = 200
            //   a4                   | movsb               byte ptr es:[edi], byte ptr [esi]
            //   44                   | inc                 esp
            //   43                   | inc                 ebx
            //   00dc                 | add                 ah, bl
            //   7442                 | je                  0x44
            //   000477               | add                 byte ptr [edi + esi*2], al

        $sequence_1 = { 73d2 1592a2ac59 fd 93 0b0d???????? 676e }
            // n = 6, score = 200
            //   73d2                 | jae                 0xffffffd4
            //   1592a2ac59           | adc                 eax, 0x59aca292
            //   fd                   | std                 
            //   93                   | xchg                eax, ebx
            //   0b0d????????         |                     
            //   676e                 | outsb               dx, byte ptr [si]

        $sequence_2 = { 04c8 fe04ec fd 04e8 }
            // n = 4, score = 200
            //   04c8                 | add                 al, 0xc8
            //   fe04ec               | inc                 byte ptr [esp + ebp*8]
            //   fd                   | std                 
            //   04e8                 | add                 al, 0xe8

        $sequence_3 = { 9c 7092 e612 2ed826 b9914e5758 22f3 }
            // n = 6, score = 200
            //   9c                   | pushfd              
            //   7092                 | jo                  0xffffff94
            //   e612                 | out                 0x12, al
            //   2ed826               | fsub                dword ptr cs:[esi]
            //   b9914e5758           | mov                 ecx, 0x58574e91
            //   22f3                 | and                 dh, bl

        $sequence_4 = { 6a14 8912 8be3 735f 84e4 44 }
            // n = 6, score = 200
            //   6a14                 | push                0x14
            //   8912                 | mov                 dword ptr [edx], edx
            //   8be3                 | mov                 esp, ebx
            //   735f                 | jae                 0x61
            //   84e4                 | test                ah, ah
            //   44                   | inc                 esp

        $sequence_5 = { 9aaed932ca4e36 e359 9d 5f }
            // n = 4, score = 200
            //   9aaed932ca4e36       | lcall               0x364e:0xca32d9ae
            //   e359                 | jecxz               0x5b
            //   9d                   | popfd               
            //   5f                   | pop                 edi

        $sequence_6 = { 7442 000477 42 0028 fa 41 0014b4 }
            // n = 7, score = 200
            //   7442                 | je                  0x44
            //   000477               | add                 byte ptr [edi + esi*2], al
            //   42                   | inc                 edx
            //   0028                 | add                 byte ptr [eax], ch
            //   fa                   | cli                 
            //   41                   | inc                 ecx
            //   0014b4               | add                 byte ptr [esp + esi*4], dl

        $sequence_7 = { 000d???????? 04e4 fd 0468 ff05???????? }
            // n = 5, score = 200
            //   000d????????         |                     
            //   04e4                 | add                 al, 0xe4
            //   fd                   | std                 
            //   0468                 | add                 al, 0x68
            //   ff05????????         |                     

        $sequence_8 = { 00e8 dd7000 008bf98b5d1c 8d4de4 }
            // n = 4, score = 100
            //   00e8                 | add                 al, ch
            //   dd7000               | fnsave              dword ptr [eax]
            //   008bf98b5d1c         | add                 byte ptr [ebx + 0x1c5d8bf9], cl
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]

        $sequence_9 = { 000f b681 fc b84500ff24 }
            // n = 4, score = 100
            //   000f                 | add                 byte ptr [edi], cl
            //   b681                 | mov                 dh, 0x81
            //   fc                   | cld                 
            //   b84500ff24           | mov                 eax, 0x24ff0045

        $sequence_10 = { 0108 8b442410 891e 894604 }
            // n = 4, score = 100
            //   0108                 | add                 dword ptr [eax], ecx
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   891e                 | mov                 dword ptr [esi], ebx
            //   894604               | mov                 dword ptr [esi + 4], eax

        $sequence_11 = { 00d1 6848004069 48 00d1 }
            // n = 4, score = 100
            //   00d1                 | add                 cl, dl
            //   6848004069           | push                0x69400048
            //   48                   | dec                 eax
            //   00d1                 | add                 cl, dl

        $sequence_12 = { 00e8 f61c00 008bd9895df0 8b451c }
            // n = 4, score = 100
            //   00e8                 | add                 al, ch
            //   f61c00               | neg                 byte ptr [eax + eax]
            //   008bd9895df0         | add                 byte ptr [ebx - 0xfa27627], cl
            //   8b451c               | mov                 eax, dword ptr [ebp + 0x1c]

        $sequence_13 = { 00856948008b ff558b ec 83ec0c }
            // n = 4, score = 100
            //   00856948008b         | add                 byte ptr [ebp - 0x74ffb797], al
            //   ff558b               | call                dword ptr [ebp - 0x75]
            //   ec                   | in                  al, dx
            //   83ec0c               | sub                 esp, 0xc

        $sequence_14 = { 00d1 6848007269 48 00856948008b }
            // n = 4, score = 100
            //   00d1                 | add                 cl, dl
            //   6848007269           | push                0x69720048
            //   48                   | dec                 eax
            //   00856948008b         | add                 byte ptr [ebp - 0x74ffb797], al

        $sequence_15 = { 0108 eb5a 8b4508 83ceff }
            // n = 4, score = 100
            //   0108                 | add                 dword ptr [eax], ecx
            //   eb5a                 | jmp                 0x5c
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83ceff               | or                  esi, 0xffffffff

    condition:
        7 of them and filesize < 1867776
}