rule win_eyservice_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.eyservice."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.eyservice"
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
        $sequence_0 = { 81ec68020000 a1???????? 33c4 89842464020000 8b842474020000 56 8bb42474020000 }
            // n = 7, score = 100
            //   81ec68020000         | sub                 esp, 0x268
            //   a1????????           |                     
            //   33c4                 | xor                 eax, esp
            //   89842464020000       | mov                 dword ptr [esp + 0x264], eax
            //   8b842474020000       | mov                 eax, dword ptr [esp + 0x274]
            //   56                   | push                esi
            //   8bb42474020000       | mov                 esi, dword ptr [esp + 0x274]

        $sequence_1 = { 59 c20400 8b7c2418 57 8bce e8???????? b944000000 }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   c20400               | ret                 4
            //   8b7c2418             | mov                 edi, dword ptr [esp + 0x18]
            //   57                   | push                edi
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   b944000000           | mov                 ecx, 0x44

        $sequence_2 = { 7516 e8???????? 57 ff15???????? 5f b80f000000 }
            // n = 6, score = 100
            //   7516                 | jne                 0x18
            //   e8????????           |                     
            //   57                   | push                edi
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   b80f000000           | mov                 eax, 0xf

        $sequence_3 = { 7504 33c0 59 c3 833d????????00 74f3 8d0c24 }
            // n = 7, score = 100
            //   7504                 | jne                 6
            //   33c0                 | xor                 eax, eax
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   833d????????00       |                     
            //   74f3                 | je                  0xfffffff5
            //   8d0c24               | lea                 ecx, dword ptr [esp]

        $sequence_4 = { 8bce e8???????? 8bf8 83ef1c 8b4c2414 8b5710 894f24 }
            // n = 7, score = 100
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   83ef1c               | sub                 edi, 0x1c
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   8b5710               | mov                 edx, dword ptr [edi + 0x10]
            //   894f24               | mov                 dword ptr [edi + 0x24], ecx

        $sequence_5 = { 52 ff15???????? 85c0 74d6 83470820 8907 8b470c }
            // n = 7, score = 100
            //   52                   | push                edx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   74d6                 | je                  0xffffffd8
            //   83470820             | add                 dword ptr [edi + 8], 0x20
            //   8907                 | mov                 dword ptr [edi], eax
            //   8b470c               | mov                 eax, dword ptr [edi + 0xc]

        $sequence_6 = { 56 8bf1 8b06 8b5010 57 8b7c2410 8b1f }
            // n = 7, score = 100
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8b5010               | mov                 edx, dword ptr [eax + 0x10]
            //   57                   | push                edi
            //   8b7c2410             | mov                 edi, dword ptr [esp + 0x10]
            //   8b1f                 | mov                 ebx, dword ptr [edi]

        $sequence_7 = { c20400 8d4640 895e3c 894644 5e 8900 }
            // n = 6, score = 100
            //   c20400               | ret                 4
            //   8d4640               | lea                 eax, dword ptr [esi + 0x40]
            //   895e3c               | mov                 dword ptr [esi + 0x3c], ebx
            //   894644               | mov                 dword ptr [esi + 0x44], eax
            //   5e                   | pop                 esi
            //   8900                 | mov                 dword ptr [eax], eax

        $sequence_8 = { 88442407 8a8654720000 0fb6d0 b908000000 }
            // n = 4, score = 100
            //   88442407             | mov                 byte ptr [esp + 7], al
            //   8a8654720000         | mov                 al, byte ptr [esi + 0x7254]
            //   0fb6d0               | movzx               edx, al
            //   b908000000           | mov                 ecx, 8

        $sequence_9 = { 5f 59 c20400 55 8b690c 3bef 764b }
            // n = 7, score = 100
            //   5f                   | pop                 edi
            //   59                   | pop                 ecx
            //   c20400               | ret                 4
            //   55                   | push                ebp
            //   8b690c               | mov                 ebp, dword ptr [ecx + 0xc]
            //   3bef                 | cmp                 ebp, edi
            //   764b                 | jbe                 0x4d

    condition:
        7 of them and filesize < 452608
}