rule win_dorkbot_ngrbot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.dorkbot_ngrbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dorkbot_ngrbot"
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
        $sequence_0 = { 3c01 7557 8b4609 668b560d b902000000 50 8945ec }
            // n = 7, score = 200
            //   3c01                 | cmp                 al, 1
            //   7557                 | jne                 0x59
            //   8b4609               | mov                 eax, dword ptr [esi + 9]
            //   668b560d             | mov                 dx, word ptr [esi + 0xd]
            //   b902000000           | mov                 ecx, 2
            //   50                   | push                eax
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax

        $sequence_1 = { e8???????? 83c408 85c0 7536 68???????? 56 e8???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   7536                 | jne                 0x38
            //   68????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_2 = { 7405 395e04 7561 c745fc9cffffff 837dfc00 0f85b9010000 ff15???????? }
            // n = 7, score = 200
            //   7405                 | je                  7
            //   395e04               | cmp                 dword ptr [esi + 4], ebx
            //   7561                 | jne                 0x63
            //   c745fc9cffffff       | mov                 dword ptr [ebp - 4], 0xffffff9c
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0
            //   0f85b9010000         | jne                 0x1bf
            //   ff15????????         |                     

        $sequence_3 = { 68???????? eb73 ffd3 8b4df8 8b55fc 50 51 }
            // n = 7, score = 200
            //   68????????           |                     
            //   eb73                 | jmp                 0x75
            //   ffd3                 | call                ebx
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   50                   | push                eax
            //   51                   | push                ecx

        $sequence_4 = { 52 46 ffd7 8b4508 83e801 743d 83e801 }
            // n = 7, score = 200
            //   52                   | push                edx
            //   46                   | inc                 esi
            //   ffd7                 | call                edi
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83e801               | sub                 eax, 1
            //   743d                 | je                  0x3f
            //   83e801               | sub                 eax, 1

        $sequence_5 = { 5d c20400 85ff 751b ff15???????? 53 57 }
            // n = 7, score = 200
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   85ff                 | test                edi, edi
            //   751b                 | jne                 0x1d
            //   ff15????????         |                     
            //   53                   | push                ebx
            //   57                   | push                edi

        $sequence_6 = { 894524 85c0 0f8cb2010000 83fe01 741d 83fe02 7418 }
            // n = 7, score = 200
            //   894524               | mov                 dword ptr [ebp + 0x24], eax
            //   85c0                 | test                eax, eax
            //   0f8cb2010000         | jl                  0x1b8
            //   83fe01               | cmp                 esi, 1
            //   741d                 | je                  0x1f
            //   83fe02               | cmp                 esi, 2
            //   7418                 | je                  0x1a

        $sequence_7 = { e8???????? 33ff 898604080000 3bc7 7512 56 e8???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   33ff                 | xor                 edi, edi
            //   898604080000         | mov                 dword ptr [esi + 0x804], eax
            //   3bc7                 | cmp                 eax, edi
            //   7512                 | jne                 0x14
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_8 = { a1???????? 52 50 8d4df8 e8???????? 8b0e 51 }
            // n = 7, score = 200
            //   a1????????           |                     
            //   52                   | push                edx
            //   50                   | push                eax
            //   8d4df8               | lea                 ecx, [ebp - 8]
            //   e8????????           |                     
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   51                   | push                ecx

        $sequence_9 = { 7514 8a55ff 80e207 80fa05 7509 83c004 eb04 }
            // n = 7, score = 200
            //   7514                 | jne                 0x16
            //   8a55ff               | mov                 dl, byte ptr [ebp - 1]
            //   80e207               | and                 dl, 7
            //   80fa05               | cmp                 dl, 5
            //   7509                 | jne                 0xb
            //   83c004               | add                 eax, 4
            //   eb04                 | jmp                 6

    condition:
        7 of them and filesize < 638976
}