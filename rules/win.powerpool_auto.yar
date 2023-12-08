rule win_powerpool_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.powerpool."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.powerpool"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
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
        $sequence_0 = { 741f 90 8b4e54 8a01 }
            // n = 4, score = 200
            //   741f                 | je                  0x21
            //   90                   | nop                 
            //   8b4e54               | mov                 ecx, dword ptr [esi + 0x54]
            //   8a01                 | mov                 al, byte ptr [ecx]

        $sequence_1 = { 7420 8b4514 8b4dfc 81c12c020000 }
            // n = 4, score = 200
            //   7420                 | je                  0x22
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   81c12c020000         | add                 ecx, 0x22c

        $sequence_2 = { 895de8 8b5dcc 2bd8 895940 8b5dd0 }
            // n = 5, score = 200
            //   895de8               | mov                 dword ptr [ebp - 0x18], ebx
            //   8b5dcc               | mov                 ebx, dword ptr [ebp - 0x34]
            //   2bd8                 | sub                 ebx, eax
            //   895940               | mov                 dword ptr [ecx + 0x40], ebx
            //   8b5dd0               | mov                 ebx, dword ptr [ebp - 0x30]

        $sequence_3 = { 005311 40 005d11 40 006711 }
            // n = 5, score = 200
            //   005311               | add                 byte ptr [ebx + 0x11], dl
            //   40                   | inc                 eax
            //   005d11               | add                 byte ptr [ebp + 0x11], bl
            //   40                   | inc                 eax
            //   006711               | add                 byte ptr [edi + 0x11], ah

        $sequence_4 = { 7420 83e91d 7412 83e903 0f8515010000 c745dcfcae4400 }
            // n = 6, score = 200
            //   7420                 | je                  0x22
            //   83e91d               | sub                 ecx, 0x1d
            //   7412                 | je                  0x14
            //   83e903               | sub                 ecx, 3
            //   0f8515010000         | jne                 0x11b
            //   c745dcfcae4400       | mov                 dword ptr [ebp - 0x24], 0x44aefc

        $sequence_5 = { 7420 3c0a 740c 6a0a 6a01 8d4b14 }
            // n = 6, score = 200
            //   7420                 | je                  0x22
            //   3c0a                 | cmp                 al, 0xa
            //   740c                 | je                  0xe
            //   6a0a                 | push                0xa
            //   6a01                 | push                1
            //   8d4b14               | lea                 ecx, [ebx + 0x14]

        $sequence_6 = { 741f d945b8 03c0 03c0 }
            // n = 4, score = 200
            //   741f                 | je                  0x21
            //   d945b8               | fld                 dword ptr [ebp - 0x48]
            //   03c0                 | add                 eax, eax
            //   03c0                 | add                 eax, eax

        $sequence_7 = { 8b5c2410 23da c1ce0a 03f2 23ee 0bdd 035c2418 }
            // n = 7, score = 200
            //   8b5c2410             | mov                 ebx, dword ptr [esp + 0x10]
            //   23da                 | and                 ebx, edx
            //   c1ce0a               | ror                 esi, 0xa
            //   03f2                 | add                 esi, edx
            //   23ee                 | and                 ebp, esi
            //   0bdd                 | or                  ebx, ebp
            //   035c2418             | add                 ebx, dword ptr [esp + 0x18]

        $sequence_8 = { 895dd0 8b7940 897dcc 3bc7 7613 }
            // n = 5, score = 200
            //   895dd0               | mov                 dword ptr [ebp - 0x30], ebx
            //   8b7940               | mov                 edi, dword ptr [ecx + 0x40]
            //   897dcc               | mov                 dword ptr [ebp - 0x34], edi
            //   3bc7                 | cmp                 eax, edi
            //   7613                 | jbe                 0x15

        $sequence_9 = { 7420 807de000 741a 8b4ddc }
            // n = 4, score = 200
            //   7420                 | je                  0x22
            //   807de000             | cmp                 byte ptr [ebp - 0x20], 0
            //   741a                 | je                  0x1c
            //   8b4ddc               | mov                 ecx, dword ptr [ebp - 0x24]

        $sequence_10 = { 006711 40 0000 0303 }
            // n = 4, score = 200
            //   006711               | add                 byte ptr [edi + 0x11], ah
            //   40                   | inc                 eax
            //   0000                 | add                 byte ptr [eax], al
            //   0303                 | add                 eax, dword ptr [ebx]

        $sequence_11 = { 7420 8b4508 8b4d0c 3bc1 }
            // n = 4, score = 200
            //   7420                 | je                  0x22
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   3bc1                 | cmp                 eax, ecx

        $sequence_12 = { 895ddc 895dfc 8d45e0 50 }
            // n = 4, score = 200
            //   895ddc               | mov                 dword ptr [ebp - 0x24], ebx
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   50                   | push                eax

        $sequence_13 = { 895de0 895de4 33c9 66898dd0fdffff }
            // n = 4, score = 200
            //   895de0               | mov                 dword ptr [ebp - 0x20], ebx
            //   895de4               | mov                 dword ptr [ebp - 0x1c], ebx
            //   33c9                 | xor                 ecx, ecx
            //   66898dd0fdffff       | mov                 word ptr [ebp - 0x230], cx

        $sequence_14 = { 895ddc 8b45e4 50 e8???????? }
            // n = 4, score = 200
            //   895ddc               | mov                 dword ptr [ebp - 0x24], ebx
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_15 = { 744f 53 57 8bff 8bc8 }
            // n = 5, score = 200
            //   744f                 | je                  0x51
            //   53                   | push                ebx
            //   57                   | push                edi
            //   8bff                 | mov                 edi, edi
            //   8bc8                 | mov                 ecx, eax

    condition:
        7 of them and filesize < 819200
}