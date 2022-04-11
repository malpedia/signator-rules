rule win_cradlecore_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.cradlecore."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cradlecore"
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
        $sequence_0 = { 50 57 ff15???????? 6a00 6a01 8d4d98 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   57                   | push                edi
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   8d4d98               | lea                 ecx, dword ptr [ebp - 0x68]

        $sequence_1 = { 830fff 8bf7 2b349df01f4300 c1fe06 8bc3 c1e005 }
            // n = 6, score = 100
            //   830fff               | or                  dword ptr [edi], 0xffffffff
            //   8bf7                 | mov                 esi, edi
            //   2b349df01f4300       | sub                 esi, dword ptr [ebx*4 + 0x431ff0]
            //   c1fe06               | sar                 esi, 6
            //   8bc3                 | mov                 eax, ebx
            //   c1e005               | shl                 eax, 5

        $sequence_2 = { 8d75f0 e8???????? 59 50 8d858cfeffff 50 8d4db0 }
            // n = 7, score = 100
            //   8d75f0               | lea                 esi, dword ptr [ebp - 0x10]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   50                   | push                eax
            //   8d858cfeffff         | lea                 eax, dword ptr [ebp - 0x174]
            //   50                   | push                eax
            //   8d4db0               | lea                 ecx, dword ptr [ebp - 0x50]

        $sequence_3 = { 7603 83c8ff 83791410 7204 8b11 }
            // n = 5, score = 100
            //   7603                 | jbe                 5
            //   83c8ff               | or                  eax, 0xffffffff
            //   83791410             | cmp                 dword ptr [ecx + 0x14], 0x10
            //   7204                 | jb                  6
            //   8b11                 | mov                 edx, dword ptr [ecx]

        $sequence_4 = { 031485f01f4300 eb05 ba???????? f6422480 7416 e8???????? }
            // n = 6, score = 100
            //   031485f01f4300       | add                 edx, dword ptr [eax*4 + 0x431ff0]
            //   eb05                 | jmp                 7
            //   ba????????           |                     
            //   f6422480             | test                byte ptr [edx + 0x24], 0x80
            //   7416                 | je                  0x18
            //   e8????????           |                     

        $sequence_5 = { 7407 57 53 e8???????? 834dfcff 8b4de0 8b01 }
            // n = 7, score = 100
            //   7407                 | je                  9
            //   57                   | push                edi
            //   53                   | push                ebx
            //   e8????????           |                     
            //   834dfcff             | or                  dword ptr [ebp - 4], 0xffffffff
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   8b01                 | mov                 eax, dword ptr [ecx]

        $sequence_6 = { 8bcf e8???????? 5e 53 ff7508 ff37 }
            // n = 6, score = 100
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   5e                   | pop                 esi
            //   53                   | push                ebx
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff37                 | push                dword ptr [edi]

        $sequence_7 = { 57 8b7d10 33db 33d2 }
            // n = 4, score = 100
            //   57                   | push                edi
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]
            //   33db                 | xor                 ebx, ebx
            //   33d2                 | xor                 edx, edx

        $sequence_8 = { ff7508 8b16 ff5238 8ac8 84c9 7505 8a4508 }
            // n = 7, score = 100
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   ff5238               | call                dword ptr [edx + 0x38]
            //   8ac8                 | mov                 cl, al
            //   84c9                 | test                cl, cl
            //   7505                 | jne                 7
            //   8a4508               | mov                 al, byte ptr [ebp + 8]

        $sequence_9 = { 8b048df01f4300 8a441826 3c0a 741c 85f6 7418 6a03 }
            // n = 7, score = 100
            //   8b048df01f4300       | mov                 eax, dword ptr [ecx*4 + 0x431ff0]
            //   8a441826             | mov                 al, byte ptr [eax + ebx + 0x26]
            //   3c0a                 | cmp                 al, 0xa
            //   741c                 | je                  0x1e
            //   85f6                 | test                esi, esi
            //   7418                 | je                  0x1a
            //   6a03                 | push                3

    condition:
        7 of them and filesize < 450560
}