rule win_romeos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.romeos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.romeos"
        malpedia_rule_date = "20211007"
        malpedia_hash = "e5b790e0f888f252d49063a1251ca60ec2832535"
        malpedia_version = "20211008"
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
        $sequence_0 = { 6a00 50 6a00 6a00 89742444 }
            // n = 5, score = 400
            //   6a00                 | push                0
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   89742444             | mov                 dword ptr [esp + 0x44], esi

        $sequence_1 = { 33c0 5b 83c408 c20c00 8b06 }
            // n = 5, score = 400
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx
            //   83c408               | add                 esp, 8
            //   c20c00               | ret                 0xc
            //   8b06                 | mov                 eax, dword ptr [esi]

        $sequence_2 = { 8d54241c 55 52 57 8bce }
            // n = 5, score = 400
            //   8d54241c             | lea                 edx, dword ptr [esp + 0x1c]
            //   55                   | push                ebp
            //   52                   | push                edx
            //   57                   | push                edi
            //   8bce                 | mov                 ecx, esi

        $sequence_3 = { e8???????? 83c408 807c24480e 7406 43 83fb08 7cb6 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   807c24480e           | cmp                 byte ptr [esp + 0x48], 0xe
            //   7406                 | je                  8
            //   43                   | inc                 ebx
            //   83fb08               | cmp                 ebx, 8
            //   7cb6                 | jl                  0xffffffb8

        $sequence_4 = { 8d44244c c644241701 50 bd30000000 e8???????? }
            // n = 5, score = 400
            //   8d44244c             | lea                 eax, dword ptr [esp + 0x4c]
            //   c644241701           | mov                 byte ptr [esp + 0x17], 1
            //   50                   | push                eax
            //   bd30000000           | mov                 ebp, 0x30
            //   e8????????           |                     

        $sequence_5 = { e8???????? 85c0 0f85ef000000 85db 751d 807c244802 }
            // n = 6, score = 400
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f85ef000000         | jne                 0xf5
            //   85db                 | test                ebx, ebx
            //   751d                 | jne                 0x1f
            //   807c244802           | cmp                 byte ptr [esp + 0x48], 2

        $sequence_6 = { 8d4c244c 6800200000 51 57 8bce e8???????? 85c0 }
            // n = 7, score = 400
            //   8d4c244c             | lea                 ecx, dword ptr [esp + 0x4c]
            //   6800200000           | push                0x2000
            //   51                   | push                ecx
            //   57                   | push                edi
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_7 = { c644244800 6a16 f3ab 66ab aa 8d44244c c644241701 }
            // n = 7, score = 400
            //   c644244800           | mov                 byte ptr [esp + 0x48], 0
            //   6a16                 | push                0x16
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8d44244c             | lea                 eax, dword ptr [esp + 0x4c]
            //   c644241701           | mov                 byte ptr [esp + 0x17], 1

        $sequence_8 = { 55 53 8d4c2424 6a01 51 }
            // n = 5, score = 200
            //   55                   | push                ebp
            //   53                   | push                ebx
            //   8d4c2424             | lea                 ecx, dword ptr [esp + 0x24]
            //   6a01                 | push                1
            //   51                   | push                ecx

        $sequence_9 = { 6a01 ff15???????? ffd5 99 f7fb }
            // n = 5, score = 200
            //   6a01                 | push                1
            //   ff15????????         |                     
            //   ffd5                 | call                ebp
            //   99                   | cdq                 
            //   f7fb                 | idiv                ebx

        $sequence_10 = { 55 ff15???????? 55 ff15???????? 8d4c2470 6a04 51 }
            // n = 7, score = 200
            //   55                   | push                ebp
            //   ff15????????         |                     
            //   55                   | push                ebp
            //   ff15????????         |                     
            //   8d4c2470             | lea                 ecx, dword ptr [esp + 0x70]
            //   6a04                 | push                4
            //   51                   | push                ecx

        $sequence_11 = { eb08 c744241801000000 8b4c2420 8b6c2424 }
            // n = 4, score = 200
            //   eb08                 | jmp                 0xa
            //   c744241801000000     | mov                 dword ptr [esp + 0x18], 1
            //   8b4c2420             | mov                 ecx, dword ptr [esp + 0x20]
            //   8b6c2424             | mov                 ebp, dword ptr [esp + 0x24]

        $sequence_12 = { 6830750000 ff15???????? 47 3bfd 0f8c4cffffff 8bce e8???????? }
            // n = 7, score = 200
            //   6830750000           | push                0x7530
            //   ff15????????         |                     
            //   47                   | inc                 edi
            //   3bfd                 | cmp                 edi, ebp
            //   0f8c4cffffff         | jl                  0xffffff52
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_13 = { 8a8884240110 8bc1 eb12 25ffff0000 c1e807 33d2 8a9084250110 }
            // n = 7, score = 200
            //   8a8884240110         | mov                 cl, byte ptr [eax + 0x10012484]
            //   8bc1                 | mov                 eax, ecx
            //   eb12                 | jmp                 0x14
            //   25ffff0000           | and                 eax, 0xffff
            //   c1e807               | shr                 eax, 7
            //   33d2                 | xor                 edx, edx
            //   8a9084250110         | mov                 dl, byte ptr [eax + 0x10012584]

        $sequence_14 = { ffd6 89442418 8d44245c 50 ffd6 8d4c2420 }
            // n = 6, score = 200
            //   ffd6                 | call                esi
            //   89442418             | mov                 dword ptr [esp + 0x18], eax
            //   8d44245c             | lea                 eax, dword ptr [esp + 0x5c]
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   8d4c2420             | lea                 ecx, dword ptr [esp + 0x20]

        $sequence_15 = { 8a9184260110 66ff849698040000 663d0001 8d8c9698040000 7311 25ffff0000 }
            // n = 6, score = 200
            //   8a9184260110         | mov                 dl, byte ptr [ecx + 0x10012684]
            //   66ff849698040000     | inc                 word ptr [esi + edx*4 + 0x498]
            //   663d0001             | cmp                 ax, 0x100
            //   8d8c9698040000       | lea                 ecx, dword ptr [esi + edx*4 + 0x498]
            //   7311                 | jae                 0x13
            //   25ffff0000           | and                 eax, 0xffff

    condition:
        7 of them and filesize < 294912
}