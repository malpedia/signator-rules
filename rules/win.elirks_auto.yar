rule win_elirks_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.elirks."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.elirks"
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
        $sequence_0 = { 85c0 74a6 6683780802 759f 6683780a04 7598 8b400c }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   74a6                 | je                  0xffffffa8
            //   6683780802           | cmp                 word ptr [eax + 8], 2
            //   759f                 | jne                 0xffffffa1
            //   6683780a04           | cmp                 word ptr [eax + 0xa], 4
            //   7598                 | jne                 0xffffff9a
            //   8b400c               | mov                 eax, dword ptr [eax + 0xc]

        $sequence_1 = { ff15???????? 57 ff15???????? 8d542408 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8d542408             | lea                 edx, dword ptr [esp + 8]

        $sequence_2 = { 897e04 c74608010000a0 5f 5e 5d 5b }
            // n = 6, score = 100
            //   897e04               | mov                 dword ptr [esi + 4], edi
            //   c74608010000a0       | mov                 dword ptr [esi + 8], 0xa0000001
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx

        $sequence_3 = { 7504 89442414 8d4b01 394c2414 }
            // n = 4, score = 100
            //   7504                 | jne                 6
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   8d4b01               | lea                 ecx, dword ptr [ebx + 1]
            //   394c2414             | cmp                 dword ptr [esp + 0x14], ecx

        $sequence_4 = { 5d 5b 81c440020000 c3 8bc7 5f 5e }
            // n = 7, score = 100
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx
            //   81c440020000         | add                 esp, 0x240
            //   c3                   | ret                 
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_5 = { 8984244cc80000 7464 8b3d???????? 33db 8d442424 }
            // n = 5, score = 100
            //   8984244cc80000       | mov                 dword ptr [esp + 0xc84c], eax
            //   7464                 | je                  0x66
            //   8b3d????????         |                     
            //   33db                 | xor                 ebx, ebx
            //   8d442424             | lea                 eax, dword ptr [esp + 0x24]

        $sequence_6 = { 68???????? 57 ff15???????? 85c0 741d 8b54240c 8b442410 }
            // n = 7, score = 100
            //   68????????           |                     
            //   57                   | push                edi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   741d                 | je                  0x1f
            //   8b54240c             | mov                 edx, dword ptr [esp + 0xc]
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]

        $sequence_7 = { 5f 5e 5b c3 8bf0 8bf9 }
            // n = 6, score = 100
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   8bf0                 | mov                 esi, eax
            //   8bf9                 | mov                 edi, ecx

        $sequence_8 = { 89742438 ff15???????? 50 56 89442424 }
            // n = 5, score = 100
            //   89742438             | mov                 dword ptr [esp + 0x38], esi
            //   ff15????????         |                     
            //   50                   | push                eax
            //   56                   | push                esi
            //   89442424             | mov                 dword ptr [esp + 0x24], eax

        $sequence_9 = { 8d4c2414 51 ff15???????? 57 }
            // n = 4, score = 100
            //   8d4c2414             | lea                 ecx, dword ptr [esp + 0x14]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   57                   | push                edi

    condition:
        7 of them and filesize < 81920
}