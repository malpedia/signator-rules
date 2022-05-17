rule win_shujin_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.shujin."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shujin"
        malpedia_rule_date = "20220513"
        malpedia_hash = "7f4b2229e6ae614d86d74917f6d5b41890e62a26"
        malpedia_version = "20220516"
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
        $sequence_0 = { 23d8 333c9de8994000 0fb6590b 23d0 333c95e8a14000 8b510a 897906 }
            // n = 7, score = 100
            //   23d8                 | and                 ebx, eax
            //   333c9de8994000       | xor                 edi, dword ptr [ebx*4 + 0x4099e8]
            //   0fb6590b             | movzx               ebx, byte ptr [ecx + 0xb]
            //   23d0                 | and                 edx, eax
            //   333c95e8a14000       | xor                 edi, dword ptr [edx*4 + 0x40a1e8]
            //   8b510a               | mov                 edx, dword ptr [ecx + 0xa]
            //   897906               | mov                 dword ptr [ecx + 6], edi

        $sequence_1 = { 8d7b2c f3a5 894320 7e17 }
            // n = 4, score = 100
            //   8d7b2c               | lea                 edi, [ebx + 0x2c]
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   894320               | mov                 dword ptr [ebx + 0x20], eax
            //   7e17                 | jle                 0x19

        $sequence_2 = { 81e7ffff1f00 8bda c1e315 0bfb 8b5df8 33cf 23da }
            // n = 7, score = 100
            //   81e7ffff1f00         | and                 edi, 0x1fffff
            //   8bda                 | mov                 ebx, edx
            //   c1e315               | shl                 ebx, 0x15
            //   0bfb                 | or                  edi, ebx
            //   8b5df8               | mov                 ebx, dword ptr [ebp - 8]
            //   33cf                 | xor                 ecx, edi
            //   23da                 | and                 ebx, edx

        $sequence_3 = { 660fbec9 83c008 18c5 9c 8d4805 ff3424 }
            // n = 6, score = 100
            //   660fbec9             | movsx               cx, cl
            //   83c008               | add                 eax, 8
            //   18c5                 | sbb                 ch, al
            //   9c                   | pushfd              
            //   8d4805               | lea                 ecx, [eax + 5]
            //   ff3424               | push                dword ptr [esp]

        $sequence_4 = { f3aa 5f c9 c3 55 8bec }
            // n = 6, score = 100
            //   f3aa                 | rep stosb           byte ptr es:[edi], al
            //   5f                   | pop                 edi
            //   c9                   | leave               
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp

        $sequence_5 = { 8801 0fb606 0fb65e01 83e003 c1e004 c1eb04 8a8418506c4000 }
            // n = 7, score = 100
            //   8801                 | mov                 byte ptr [ecx], al
            //   0fb606               | movzx               eax, byte ptr [esi]
            //   0fb65e01             | movzx               ebx, byte ptr [esi + 1]
            //   83e003               | and                 eax, 3
            //   c1e004               | shl                 eax, 4
            //   c1eb04               | shr                 ebx, 4
            //   8a8418506c4000       | mov                 al, byte ptr [eax + ebx + 0x406c50]

        $sequence_6 = { 57 8b7c240c 8bf1 8d4660 50 68f1030000 57 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   8b7c240c             | mov                 edi, dword ptr [esp + 0xc]
            //   8bf1                 | mov                 esi, ecx
            //   8d4660               | lea                 eax, [esi + 0x60]
            //   50                   | push                eax
            //   68f1030000           | push                0x3f1
            //   57                   | push                edi

        $sequence_7 = { ff05???????? 56 be???????? 381d???????? 740f 56 ff15???????? }
            // n = 7, score = 100
            //   ff05????????         |                     
            //   56                   | push                esi
            //   be????????           |                     
            //   381d????????         |                     
            //   740f                 | je                  0x11
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_8 = { ff15???????? 33ff 8b4508 3bc7 7402 8938 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   33ff                 | xor                 edi, edi
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   3bc7                 | cmp                 eax, edi
            //   7402                 | je                  4
            //   8938                 | mov                 dword ptr [eax], edi

        $sequence_9 = { 50 6a02 8d45f8 50 ff75fc ff15???????? 83f801 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   6a02                 | push                2
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff15????????         |                     
            //   83f801               | cmp                 eax, 1

    condition:
        7 of them and filesize < 172032
}