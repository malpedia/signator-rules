rule win_betabot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.betabot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.betabot"
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
        $sequence_0 = { 8918 ebe5 391d???????? 74dd 6878040000 e8???????? 8bf0 }
            // n = 7, score = 400
            //   8918                 | mov                 dword ptr [eax], ebx
            //   ebe5                 | jmp                 0xffffffe7
            //   391d????????         |                     
            //   74dd                 | je                  0xffffffdf
            //   6878040000           | push                0x478
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_1 = { e8???????? be04010000 56 53 8d85d4fbffff 50 }
            // n = 6, score = 400
            //   e8????????           |                     
            //   be04010000           | mov                 esi, 0x104
            //   56                   | push                esi
            //   53                   | push                ebx
            //   8d85d4fbffff         | lea                 eax, dword ptr [ebp - 0x42c]
            //   50                   | push                eax

        $sequence_2 = { 83c40c 8d8588fbffff 50 8d45e0 50 ff15???????? 8bd8 }
            // n = 7, score = 400
            //   83c40c               | add                 esp, 0xc
            //   8d8588fbffff         | lea                 eax, dword ptr [ebp - 0x478]
            //   50                   | push                eax
            //   8d45e0               | lea                 eax, dword ptr [ebp - 0x20]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax

        $sequence_3 = { 7910 6afe 58 eb18 668b0c42 663b4d08 7408 }
            // n = 7, score = 400
            //   7910                 | jns                 0x12
            //   6afe                 | push                -2
            //   58                   | pop                 eax
            //   eb18                 | jmp                 0x1a
            //   668b0c42             | mov                 cx, word ptr [edx + eax*2]
            //   663b4d08             | cmp                 cx, word ptr [ebp + 8]
            //   7408                 | je                  0xa

        $sequence_4 = { e8???????? 6a00 ffb5d0feffff ff15???????? 68c8000000 ff15???????? }
            // n = 6, score = 400
            //   e8????????           |                     
            //   6a00                 | push                0
            //   ffb5d0feffff         | push                dword ptr [ebp - 0x130]
            //   ff15????????         |                     
            //   68c8000000           | push                0xc8
            //   ff15????????         |                     

        $sequence_5 = { ff7014 ff15???????? ebac 8b45fc ff700c ff15???????? eb93 }
            // n = 7, score = 400
            //   ff7014               | push                dword ptr [eax + 0x14]
            //   ff15????????         |                     
            //   ebac                 | jmp                 0xffffffae
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   ff700c               | push                dword ptr [eax + 0xc]
            //   ff15????????         |                     
            //   eb93                 | jmp                 0xffffff95

        $sequence_6 = { e8???????? 84c0 7504 6a04 eb02 6a03 58 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7504                 | jne                 6
            //   6a04                 | push                4
            //   eb02                 | jmp                 4
            //   6a03                 | push                3
            //   58                   | pop                 eax

        $sequence_7 = { eb07 8b45e4 40 8945e4 837de410 7315 }
            // n = 6, score = 400
            //   eb07                 | jmp                 9
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   40                   | inc                 eax
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   837de410             | cmp                 dword ptr [ebp - 0x1c], 0x10
            //   7315                 | jae                 0x17

        $sequence_8 = { 40 8945e4 837de410 7315 8b45f8 0345e4 0fb600 }
            // n = 7, score = 400
            //   40                   | inc                 eax
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   837de410             | cmp                 dword ptr [ebp - 0x1c], 0x10
            //   7315                 | jae                 0x17
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   0345e4               | add                 eax, dword ptr [ebp - 0x1c]
            //   0fb600               | movzx               eax, byte ptr [eax]

        $sequence_9 = { 8b45e4 5e c9 c20800 55 8bec 83ec20 }
            // n = 7, score = 400
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   5e                   | pop                 esi
            //   c9                   | leave               
            //   c20800               | ret                 8
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec20               | sub                 esp, 0x20

    condition:
        7 of them and filesize < 835584
}