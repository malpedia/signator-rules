rule win_unidentified_073_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.unidentified_073."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_073"
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
        $sequence_0 = { 68???????? e8???????? 83ec1c c68424b803000034 8bcc 8964244c }
            // n = 6, score = 200
            //   68????????           |                     
            //   e8????????           |                     
            //   83ec1c               | sub                 esp, 0x1c
            //   c68424b803000034     | mov                 byte ptr [esp + 0x3b8], 0x34
            //   8bcc                 | mov                 ecx, esp
            //   8964244c             | mov                 dword ptr [esp + 0x4c], esp

        $sequence_1 = { bb430032be 43 00c7 c14300b3 c6430000 0404 0401 }
            // n = 7, score = 200
            //   bb430032be           | mov                 ebx, 0xbe320043
            //   43                   | inc                 ebx
            //   00c7                 | add                 bh, al
            //   c14300b3             | rol                 dword ptr [ebx], 0xb3
            //   c6430000             | mov                 byte ptr [ebx], 0
            //   0404                 | add                 al, 4
            //   0401                 | add                 al, 1

        $sequence_2 = { e8???????? 83c40c 85ff 7517 68e20a0000 68???????? 68???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85ff                 | test                edi, edi
            //   7517                 | jne                 0x19
            //   68e20a0000           | push                0xae2
            //   68????????           |                     
            //   68????????           |                     

        $sequence_3 = { 83c10c e8???????? 8945f4 eb07 c745f4c0894800 8b45f4 8be5 }
            // n = 7, score = 200
            //   83c10c               | add                 ecx, 0xc
            //   e8????????           |                     
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   eb07                 | jmp                 9
            //   c745f4c0894800       | mov                 dword ptr [ebp - 0xc], 0x4889c0
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8be5                 | mov                 esp, ebp

        $sequence_4 = { 8bc6 c747180f000000 c7471400000000 c6470400 5f 5e 5d }
            // n = 7, score = 200
            //   8bc6                 | mov                 eax, esi
            //   c747180f000000       | mov                 dword ptr [edi + 0x18], 0xf
            //   c7471400000000       | mov                 dword ptr [edi + 0x14], 0
            //   c6470400             | mov                 byte ptr [edi + 4], 0
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp

        $sequence_5 = { c1e106 8b1485d06d4a00 8995c4efffff 898dd0efffff 8b85d0efffff 8b8dc4efffff 8b95c8efffff }
            // n = 7, score = 200
            //   c1e106               | shl                 ecx, 6
            //   8b1485d06d4a00       | mov                 edx, dword ptr [eax*4 + 0x4a6dd0]
            //   8995c4efffff         | mov                 dword ptr [ebp - 0x103c], edx
            //   898dd0efffff         | mov                 dword ptr [ebp - 0x1030], ecx
            //   8b85d0efffff         | mov                 eax, dword ptr [ebp - 0x1030]
            //   8b8dc4efffff         | mov                 ecx, dword ptr [ebp - 0x103c]
            //   8b95c8efffff         | mov                 edx, dword ptr [ebp - 0x1038]

        $sequence_6 = { 8b55e0 c1fa05 8b45e0 83e01f c1e006 030495d06d4a00 8945e4 }
            // n = 7, score = 200
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]
            //   c1fa05               | sar                 edx, 5
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   83e01f               | and                 eax, 0x1f
            //   c1e006               | shl                 eax, 6
            //   030495d06d4a00       | add                 eax, dword ptr [edx*4 + 0x4a6dd0]
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax

        $sequence_7 = { 8d45c4 50 8d041f 50 52 ff75b8 ff5618 }
            // n = 7, score = 200
            //   8d45c4               | lea                 eax, [ebp - 0x3c]
            //   50                   | push                eax
            //   8d041f               | lea                 eax, [edi + ebx]
            //   50                   | push                eax
            //   52                   | push                edx
            //   ff75b8               | push                dword ptr [ebp - 0x48]
            //   ff5618               | call                dword ptr [esi + 0x18]

        $sequence_8 = { c60100 8b55ec 83c201 8955ec 8b45ec c60000 }
            // n = 6, score = 200
            //   c60100               | mov                 byte ptr [ecx], 0
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   83c201               | add                 edx, 1
            //   8955ec               | mov                 dword ptr [ebp - 0x14], edx
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   c60000               | mov                 byte ptr [eax], 0

        $sequence_9 = { 6a00 8d4508 50 8d4dd4 e8???????? 68???????? 8d4db8 }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   8d4508               | lea                 eax, [ebp + 8]
            //   50                   | push                eax
            //   8d4dd4               | lea                 ecx, [ebp - 0x2c]
            //   e8????????           |                     
            //   68????????           |                     
            //   8d4db8               | lea                 ecx, [ebp - 0x48]

    condition:
        7 of them and filesize < 1974272
}