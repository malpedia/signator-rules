rule win_bbsrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.bbsrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bbsrat"
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
        $sequence_0 = { 751f 8b4b28 57 51 c74318bcc30210 befdffffff }
            // n = 6, score = 100
            //   751f                 | jne                 0x21
            //   8b4b28               | mov                 ecx, dword ptr [ebx + 0x28]
            //   57                   | push                edi
            //   51                   | push                ecx
            //   c74318bcc30210       | mov                 dword ptr [ebx + 0x18], 0x1002c3bc
            //   befdffffff           | mov                 esi, 0xfffffffd

        $sequence_1 = { 55 52 896c241c e8???????? 8b842488040000 83c40c 83c0f0 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   52                   | push                edx
            //   896c241c             | mov                 dword ptr [esp + 0x1c], ebp
            //   e8????????           |                     
            //   8b842488040000       | mov                 eax, dword ptr [esp + 0x488]
            //   83c40c               | add                 esp, 0xc
            //   83c0f0               | add                 eax, -0x10

        $sequence_2 = { e8???????? 83c404 eb55 8b442424 83f806 751e 8d94243c010000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   eb55                 | jmp                 0x57
            //   8b442424             | mov                 eax, dword ptr [esp + 0x24]
            //   83f806               | cmp                 eax, 6
            //   751e                 | jne                 0x20
            //   8d94243c010000       | lea                 edx, dword ptr [esp + 0x13c]

        $sequence_3 = { 50 8d4f10 6864020000 51 e8???????? 83c420 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   8d4f10               | lea                 ecx, dword ptr [edi + 0x10]
            //   6864020000           | push                0x264
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c420               | add                 esp, 0x20

        $sequence_4 = { e8???????? 8b4718 8d7710 83c40c 03c6 8d542430 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b4718               | mov                 eax, dword ptr [edi + 0x18]
            //   8d7710               | lea                 esi, dword ptr [edi + 0x10]
            //   83c40c               | add                 esp, 0xc
            //   03c6                 | add                 eax, esi
            //   8d542430             | lea                 edx, dword ptr [esp + 0x30]
            //   e8????????           |                     

        $sequence_5 = { ff15???????? 8bf0 85f6 7412 8d442404 50 ff15???????? }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   7412                 | je                  0x14
            //   8d442404             | lea                 eax, dword ptr [esp + 4]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_6 = { 8be5 5d c20c00 51 e8???????? 8be5 5d }
            // n = 7, score = 100
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20c00               | ret                 0xc
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp

        $sequence_7 = { 8d44240c 50 8b44240c 8d8c2420020000 51 8d542418 52 }
            // n = 7, score = 100
            //   8d44240c             | lea                 eax, dword ptr [esp + 0xc]
            //   50                   | push                eax
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   8d8c2420020000       | lea                 ecx, dword ptr [esp + 0x220]
            //   51                   | push                ecx
            //   8d542418             | lea                 edx, dword ptr [esp + 0x18]
            //   52                   | push                edx

        $sequence_8 = { 8b7e28 8b4e58 2bfd 4f 0faf7e70 037e5c }
            // n = 6, score = 100
            //   8b7e28               | mov                 edi, dword ptr [esi + 0x28]
            //   8b4e58               | mov                 ecx, dword ptr [esi + 0x58]
            //   2bfd                 | sub                 edi, ebp
            //   4f                   | dec                 edi
            //   0faf7e70             | imul                edi, dword ptr [esi + 0x70]
            //   037e5c               | add                 edi, dword ptr [esi + 0x5c]

        $sequence_9 = { 83c420 6a3a 56 6868001100 55 e8???????? 56 }
            // n = 7, score = 100
            //   83c420               | add                 esp, 0x20
            //   6a3a                 | push                0x3a
            //   56                   | push                esi
            //   6868001100           | push                0x110068
            //   55                   | push                ebp
            //   e8????????           |                     
            //   56                   | push                esi

    condition:
        7 of them and filesize < 434176
}