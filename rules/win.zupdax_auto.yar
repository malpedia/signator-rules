rule win_zupdax_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.zupdax."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zupdax"
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
        $sequence_0 = { 2bc2 50 8d54241c 52 }
            // n = 4, score = 300
            //   2bc2                 | sub                 eax, edx
            //   50                   | push                eax
            //   8d54241c             | lea                 edx, dword ptr [esp + 0x1c]
            //   52                   | push                edx

        $sequence_1 = { 51 8b4624 53 33db 57 3bc3 7419 }
            // n = 7, score = 300
            //   51                   | push                ecx
            //   8b4624               | mov                 eax, dword ptr [esi + 0x24]
            //   53                   | push                ebx
            //   33db                 | xor                 ebx, ebx
            //   57                   | push                edi
            //   3bc3                 | cmp                 eax, ebx
            //   7419                 | je                  0x1b

        $sequence_2 = { c74604ffffffff e8???????? 68c8000000 8d4e7c 6a00 }
            // n = 5, score = 300
            //   c74604ffffffff       | mov                 dword ptr [esi + 4], 0xffffffff
            //   e8????????           |                     
            //   68c8000000           | push                0xc8
            //   8d4e7c               | lea                 ecx, dword ptr [esi + 0x7c]
            //   6a00                 | push                0

        $sequence_3 = { 895e24 895e28 895e2c e8???????? 8b460c 83c404 3bc3 }
            // n = 7, score = 300
            //   895e24               | mov                 dword ptr [esi + 0x24], ebx
            //   895e28               | mov                 dword ptr [esi + 0x28], ebx
            //   895e2c               | mov                 dword ptr [esi + 0x2c], ebx
            //   e8????????           |                     
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]
            //   83c404               | add                 esp, 4
            //   3bc3                 | cmp                 eax, ebx

        $sequence_4 = { 33db 57 3bc3 7419 8b4c2408 8b7e28 51 }
            // n = 7, score = 300
            //   33db                 | xor                 ebx, ebx
            //   57                   | push                edi
            //   3bc3                 | cmp                 eax, ebx
            //   7419                 | je                  0x1b
            //   8b4c2408             | mov                 ecx, dword ptr [esp + 8]
            //   8b7e28               | mov                 edi, dword ptr [esi + 0x28]
            //   51                   | push                ecx

        $sequence_5 = { 895e10 895e14 e8???????? 83c404 5f 5b }
            // n = 6, score = 300
            //   895e10               | mov                 dword ptr [esi + 0x10], ebx
            //   895e14               | mov                 dword ptr [esi + 0x14], ebx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx

        $sequence_6 = { 8d442404 68???????? 50 e8???????? 83c40c 6a00 8d4c2404 }
            // n = 7, score = 300
            //   8d442404             | lea                 eax, dword ptr [esp + 4]
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a00                 | push                0
            //   8d4c2404             | lea                 ecx, dword ptr [esp + 4]

        $sequence_7 = { 8d442416 50 6689542418 e8???????? 83c418 }
            // n = 5, score = 300
            //   8d442416             | lea                 eax, dword ptr [esp + 0x16]
            //   50                   | push                eax
            //   6689542418           | mov                 word ptr [esp + 0x18], dx
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18

        $sequence_8 = { e8???????? 83c408 8b06 50 895e0c 895e10 895e14 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   50                   | push                eax
            //   895e0c               | mov                 dword ptr [esi + 0xc], ebx
            //   895e10               | mov                 dword ptr [esi + 0x10], ebx
            //   895e14               | mov                 dword ptr [esi + 0x14], ebx

        $sequence_9 = { 7419 8b4c2408 8b7e28 51 }
            // n = 4, score = 300
            //   7419                 | je                  0x1b
            //   8b4c2408             | mov                 ecx, dword ptr [esp + 8]
            //   8b7e28               | mov                 edi, dword ptr [esi + 0x28]
            //   51                   | push                ecx

    condition:
        7 of them and filesize < 1032192
}