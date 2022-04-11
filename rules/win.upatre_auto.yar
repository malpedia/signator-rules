rule win_upatre_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.upatre."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.upatre"
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
        $sequence_0 = { 66ab 33c0 66ab bbff0f0000 8b75f0 56 53 }
            // n = 7, score = 200
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   33c0                 | xor                 eax, eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   bbff0f0000           | mov                 ebx, 0xfff
            //   8b75f0               | mov                 esi, dword ptr [ebp - 0x10]
            //   56                   | push                esi
            //   53                   | push                ebx

        $sequence_1 = { b02f 66ab ff7590 33c0 b404 57 03f8 }
            // n = 7, score = 200
            //   b02f                 | mov                 al, 0x2f
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   ff7590               | push                dword ptr [ebp - 0x70]
            //   33c0                 | xor                 eax, eax
            //   b404                 | mov                 ah, 4
            //   57                   | push                edi
            //   03f8                 | add                 edi, eax

        $sequence_2 = { 8b45a8 b402 ff5504 8acc c1e102 8b45f8 03c1 }
            // n = 7, score = 200
            //   8b45a8               | mov                 eax, dword ptr [ebp - 0x58]
            //   b402                 | mov                 ah, 2
            //   ff5504               | call                dword ptr [ebp + 4]
            //   8acc                 | mov                 cl, ah
            //   c1e102               | shl                 ecx, 2
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   03c1                 | add                 eax, ecx

        $sequence_3 = { 40 d1e0 50 33c0 50 6880000000 }
            // n = 6, score = 200
            //   40                   | inc                 eax
            //   d1e0                 | shl                 eax, 1
            //   50                   | push                eax
            //   33c0                 | xor                 eax, eax
            //   50                   | push                eax
            //   6880000000           | push                0x80

        $sequence_4 = { 85c0 75f9 53 ff7504 ff5500 8945f8 }
            // n = 6, score = 200
            //   85c0                 | test                eax, eax
            //   75f9                 | jne                 0xfffffffb
            //   53                   | push                ebx
            //   ff7504               | push                dword ptr [ebp + 4]
            //   ff5500               | call                dword ptr [ebp]
            //   8945f8               | mov                 dword ptr [ebp - 8], eax

        $sequence_5 = { 33c0 8945e0 8d75e0 8b7dbc }
            // n = 4, score = 200
            //   33c0                 | xor                 eax, eax
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   8d75e0               | lea                 esi, dword ptr [ebp - 0x20]
            //   8b7dbc               | mov                 edi, dword ptr [ebp - 0x44]

        $sequence_6 = { ad 0430 66ab 81c60e010000 ac 3c01 }
            // n = 6, score = 200
            //   ad                   | lodsd               eax, dword ptr [esi]
            //   0430                 | add                 al, 0x30
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   81c60e010000         | add                 esi, 0x10e
            //   ac                   | lodsb               al, byte ptr [esi]
            //   3c01                 | cmp                 al, 1

        $sequence_7 = { 33c9 66ad 6685c0 7404 }
            // n = 4, score = 200
            //   33c9                 | xor                 ecx, ecx
            //   66ad                 | lodsw               ax, word ptr [esi]
            //   6685c0               | test                ax, ax
            //   7404                 | je                  6

        $sequence_8 = { 6a00 e8???????? 8945fc 8b45dc }
            // n = 4, score = 100
            //   6a00                 | push                0
            //   e8????????           |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]

        $sequence_9 = { 83ec4c c745ec00000000 c645dc6e c645dd74 }
            // n = 4, score = 100
            //   83ec4c               | sub                 esp, 0x4c
            //   c745ec00000000       | mov                 dword ptr [ebp - 0x14], 0
            //   c645dc6e             | mov                 byte ptr [ebp - 0x24], 0x6e
            //   c645dd74             | mov                 byte ptr [ebp - 0x23], 0x74

        $sequence_10 = { 51 e8???????? 8b55d8 8955f4 }
            // n = 4, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8b55d8               | mov                 edx, dword ptr [ebp - 0x28]
            //   8955f4               | mov                 dword ptr [ebp - 0xc], edx

        $sequence_11 = { 8b45e8 8b4810 51 e8???????? 83c404 0fb7d0 8b4514 }
            // n = 7, score = 100
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   8b4810               | mov                 ecx, dword ptr [eax + 0x10]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   0fb7d0               | movzx               edx, ax
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]

        $sequence_12 = { ebac 8b55ec 83c201 8955ec c745d000000000 8b45e0 50 }
            // n = 7, score = 100
            //   ebac                 | jmp                 0xffffffae
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   83c201               | add                 edx, 1
            //   8955ec               | mov                 dword ptr [ebp - 0x14], edx
            //   c745d000000000       | mov                 dword ptr [ebp - 0x30], 0
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   50                   | push                eax

        $sequence_13 = { 7516 8b55f8 52 8b45fc }
            // n = 4, score = 100
            // 
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   52                   | push                edx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_14 = { 6a06 e8???????? 83c410 8945e0 837de000 0f8409010000 }
            // n = 6, score = 100
            //   6a06                 | push                6
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   837de000             | cmp                 dword ptr [ebp - 0x20], 0
            //   0f8409010000         | je                  0x10f

        $sequence_15 = { 837dd800 7410 6800800000 6a00 8b55d8 52 e8???????? }
            // n = 7, score = 100
            //   837dd800             | cmp                 dword ptr [ebp - 0x28], 0
            //   7410                 | je                  0x12
            //   6800800000           | push                0x8000
            //   6a00                 | push                0
            //   8b55d8               | mov                 edx, dword ptr [ebp - 0x28]
            //   52                   | push                edx
            //   e8????????           |                     

    condition:
        7 of them and filesize < 294912
}