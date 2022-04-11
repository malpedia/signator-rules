rule win_dairy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.dairy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dairy"
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
        $sequence_0 = { 8d440c40 8b0d???????? 50 51 e8???????? }
            // n = 5, score = 100
            //   8d440c40             | lea                 eax, dword ptr [esp + ecx + 0x40]
            //   8b0d????????         |                     
            //   50                   | push                eax
            //   51                   | push                ecx
            //   e8????????           |                     

        $sequence_1 = { 57 e8???????? 83f8ff 7430 3bc6 742c 8b442420 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   e8????????           |                     
            //   83f8ff               | cmp                 eax, -1
            //   7430                 | je                  0x32
            //   3bc6                 | cmp                 eax, esi
            //   742c                 | je                  0x2e
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]

        $sequence_2 = { f2ae f7d1 49 83f937 7f3b ba38000000 2bd1 }
            // n = 7, score = 100
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx
            //   83f937               | cmp                 ecx, 0x37
            //   7f3b                 | jg                  0x3d
            //   ba38000000           | mov                 edx, 0x38
            //   2bd1                 | sub                 edx, ecx

        $sequence_3 = { 03d8 2bf0 85f6 7fb8 5f 8bc5 5e }
            // n = 7, score = 100
            //   03d8                 | add                 ebx, eax
            //   2bf0                 | sub                 esi, eax
            //   85f6                 | test                esi, esi
            //   7fb8                 | jg                  0xffffffba
            //   5f                   | pop                 edi
            //   8bc5                 | mov                 eax, ebp
            //   5e                   | pop                 esi

        $sequence_4 = { b804030980 5b 83c44c c3 837c245405 }
            // n = 5, score = 100
            //   b804030980           | mov                 eax, 0x80090304
            //   5b                   | pop                 ebx
            //   83c44c               | add                 esp, 0x4c
            //   c3                   | ret                 
            //   837c245405           | cmp                 dword ptr [esp + 0x54], 5

        $sequence_5 = { 6a10 8b11 8d4c2414 51 53 }
            // n = 5, score = 100
            //   6a10                 | push                0x10
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   8d4c2414             | lea                 ecx, dword ptr [esp + 0x14]
            //   51                   | push                ecx
            //   53                   | push                ebx

        $sequence_6 = { f3a4 75cc 8d7c243c 83c9ff }
            // n = 4, score = 100
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   75cc                 | jne                 0xffffffce
            //   8d7c243c             | lea                 edi, dword ptr [esp + 0x3c]
            //   83c9ff               | or                  ecx, 0xffffffff

        $sequence_7 = { 5e 81c408010000 c3 8b442408 8d54240c 52 }
            // n = 6, score = 100
            //   5e                   | pop                 esi
            //   81c408010000         | add                 esp, 0x108
            //   c3                   | ret                 
            //   8b442408             | mov                 eax, dword ptr [esp + 8]
            //   8d54240c             | lea                 edx, dword ptr [esp + 0xc]
            //   52                   | push                edx

        $sequence_8 = { f3a4 75c2 5d 5b bf???????? 83c9ff 33c0 }
            // n = 7, score = 100
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   75c2                 | jne                 0xffffffc4
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx
            //   bf????????           |                     
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax

        $sequence_9 = { 57 6a18 e8???????? 8bb424280a0000 8b1d???????? b906000000 8bf8 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   6a18                 | push                0x18
            //   e8????????           |                     
            //   8bb424280a0000       | mov                 esi, dword ptr [esp + 0xa28]
            //   8b1d????????         |                     
            //   b906000000           | mov                 ecx, 6
            //   8bf8                 | mov                 edi, eax

    condition:
        7 of them and filesize < 212992
}