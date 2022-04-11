rule win_fakerean_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.fakerean."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fakerean"
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
        $sequence_0 = { 8b45ec 8945c4 8b45c8 898684030000 6a01 8d45b4 }
            // n = 6, score = 300
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8945c4               | mov                 dword ptr [ebp - 0x3c], eax
            //   8b45c8               | mov                 eax, dword ptr [ebp - 0x38]
            //   898684030000         | mov                 dword ptr [esi + 0x384], eax
            //   6a01                 | push                1
            //   8d45b4               | lea                 eax, dword ptr [ebp - 0x4c]

        $sequence_1 = { 85c0 0f85fd000000 57 6a05 ff35???????? ff15???????? 6a00 }
            // n = 7, score = 300
            //   85c0                 | test                eax, eax
            //   0f85fd000000         | jne                 0x103
            //   57                   | push                edi
            //   6a05                 | push                5
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   6a00                 | push                0

        $sequence_2 = { 68???????? ff35???????? e8???????? 83c418 68???????? }
            // n = 5, score = 300
            //   68????????           |                     
            //   ff35????????         |                     
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   68????????           |                     

        $sequence_3 = { 55 8bec 837d0800 7416 2bd0 0fb70c02 668908 }
            // n = 7, score = 300
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   7416                 | je                  0x18
            //   2bd0                 | sub                 edx, eax
            //   0fb70c02             | movzx               ecx, word ptr [edx + eax]
            //   668908               | mov                 word ptr [eax], cx

        $sequence_4 = { 8a07 8845f8 84c9 7419 8b4508 }
            // n = 5, score = 300
            //   8a07                 | mov                 al, byte ptr [edi]
            //   8845f8               | mov                 byte ptr [ebp - 8], al
            //   84c9                 | test                cl, cl
            //   7419                 | je                  0x1b
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_5 = { 8d45fc 50 6a18 8d45e4 50 6a00 56 }
            // n = 7, score = 300
            //   8d45fc               | lea                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax
            //   6a18                 | push                0x18
            //   8d45e4               | lea                 eax, dword ptr [ebp - 0x1c]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   56                   | push                esi

        $sequence_6 = { 33c0 398bf0030000 eb38 83fe6f 750f 8bb3f8030000 f7de }
            // n = 7, score = 300
            //   33c0                 | xor                 eax, eax
            //   398bf0030000         | cmp                 dword ptr [ebx + 0x3f0], ecx
            //   eb38                 | jmp                 0x3a
            //   83fe6f               | cmp                 esi, 0x6f
            //   750f                 | jne                 0x11
            //   8bb3f8030000         | mov                 esi, dword ptr [ebx + 0x3f8]
            //   f7de                 | neg                 esi

        $sequence_7 = { 85c0 752a 57 6a3c 68???????? e8???????? 83c40c }
            // n = 7, score = 300
            //   85c0                 | test                eax, eax
            //   752a                 | jne                 0x2c
            //   57                   | push                edi
            //   6a3c                 | push                0x3c
            //   68????????           |                     
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_8 = { 75f7 8b5508 2bd0 0fb70c02 668908 83c002 6685c9 }
            // n = 7, score = 300
            //   75f7                 | jne                 0xfffffff9
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   2bd0                 | sub                 edx, eax
            //   0fb70c02             | movzx               ecx, word ptr [edx + eax]
            //   668908               | mov                 word ptr [eax], cx
            //   83c002               | add                 eax, 2
            //   6685c9               | test                cx, cx

        $sequence_9 = { 56 33f6 57 397508 0f840a010000 ff7508 56 }
            // n = 7, score = 300
            //   56                   | push                esi
            //   33f6                 | xor                 esi, esi
            //   57                   | push                edi
            //   397508               | cmp                 dword ptr [ebp + 8], esi
            //   0f840a010000         | je                  0x110
            //   ff7508               | push                dword ptr [ebp + 8]
            //   56                   | push                esi

    condition:
        7 of them and filesize < 4071424
}