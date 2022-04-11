rule win_keyboy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.keyboy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.keyboy"
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
        $sequence_0 = { 6a00 8945f2 8d45f8 50 6a0e 8d45e8 }
            // n = 6, score = 600
            //   6a00                 | push                0
            //   8945f2               | mov                 dword ptr [ebp - 0xe], eax
            //   8d45f8               | lea                 eax, dword ptr [ebp - 8]
            //   50                   | push                eax
            //   6a0e                 | push                0xe
            //   8d45e8               | lea                 eax, dword ptr [ebp - 0x18]

        $sequence_1 = { 8bf0 85f6 741f 6a00 ff15???????? 6a00 }
            // n = 6, score = 600
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   741f                 | je                  0x21
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   6a00                 | push                0

        $sequence_2 = { 51 ff75d8 6a00 ff75c0 }
            // n = 4, score = 600
            //   51                   | push                ecx
            //   ff75d8               | push                dword ptr [ebp - 0x28]
            //   6a00                 | push                0
            //   ff75c0               | push                dword ptr [ebp - 0x40]

        $sequence_3 = { c3 3b0d???????? f27502 f2c3 f2e953030000 55 8bec }
            // n = 7, score = 500
            //   c3                   | ret                 
            //   3b0d????????         |                     
            //   f27502               | bnd jne             5
            //   f2c3                 | bnd ret             
            //   f2e953030000         | bnd jmp             0x359
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp

        $sequence_4 = { c705????????890e9944 c705????????dbd99823 c705????????d468bcb5 c705????????2086e659 c705????????eec45abf }
            // n = 5, score = 500
            //   c705????????890e9944     |     
            //   c705????????dbd99823     |     
            //   c705????????d468bcb5     |     
            //   c705????????2086e659     |     
            //   c705????????eec45abf     |     

        $sequence_5 = { c705????????a856701f c705????????597e743c c705????????0a9769e0 c705????????c4b85363 c705????????3abf261f c705????????890e9944 }
            // n = 6, score = 500
            //   c705????????a856701f     |     
            //   c705????????597e743c     |     
            //   c705????????0a9769e0     |     
            //   c705????????c4b85363     |     
            //   c705????????3abf261f     |     
            //   c705????????890e9944     |     

        $sequence_6 = { 8b4604 0345fc 50 8b45f8 03c1 50 e8???????? }
            // n = 7, score = 400
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   0345fc               | add                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   03c1                 | add                 eax, ecx
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_7 = { b901000000 eb0f 3cfe 7509 }
            // n = 4, score = 400
            //   b901000000           | mov                 ecx, 1
            //   eb0f                 | jmp                 0x11
            //   3cfe                 | cmp                 al, 0xfe
            //   7509                 | jne                 0xb

        $sequence_8 = { 7cd6 5f 5e 8be5 5d c3 }
            // n = 6, score = 400
            //   7cd6                 | jl                  0xffffffd8
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 

        $sequence_9 = { c7852cfdffff07000100 50 ff7304 ff15???????? }
            // n = 4, score = 400
            //   c7852cfdffff07000100     | mov    dword ptr [ebp - 0x2d4], 0x10007
            //   50                   | push                eax
            //   ff7304               | push                dword ptr [ebx + 4]
            //   ff15????????         |                     

        $sequence_10 = { c705????????34fbfb41 c705????????e6cd2b66 c705????????79e66d38 c705????????ba66ea37 c705????????1671e665 c705????????f3106cb3 c705????????526c1ed0 }
            // n = 7, score = 400
            //   c705????????34fbfb41     |     
            //   c705????????e6cd2b66     |     
            //   c705????????79e66d38     |     
            //   c705????????ba66ea37     |     
            //   c705????????1671e665     |     
            //   c705????????f3106cb3     |     
            //   c705????????526c1ed0     |     

        $sequence_11 = { 2408 f6d8 1ac0 24dd 88474e }
            // n = 5, score = 400
            //   2408                 | and                 al, 8
            //   f6d8                 | neg                 al
            //   1ac0                 | sbb                 al, al
            //   24dd                 | and                 al, 0xdd
            //   88474e               | mov                 byte ptr [edi + 0x4e], al

        $sequence_12 = { 0fbe4c8de0 3401 0fbec0 0fafc8 80f185 880c3e 46 }
            // n = 7, score = 400
            //   0fbe4c8de0           | movsx               ecx, byte ptr [ebp + ecx*4 - 0x20]
            //   3401                 | xor                 al, 1
            //   0fbec0               | movsx               eax, al
            //   0fafc8               | imul                ecx, eax
            //   80f185               | xor                 cl, 0x85
            //   880c3e               | mov                 byte ptr [esi + edi], cl
            //   46                   | inc                 esi

        $sequence_13 = { 8d46d6 99 83e23f 03c2 }
            // n = 4, score = 400
            //   8d46d6               | lea                 eax, dword ptr [esi - 0x2a]
            //   99                   | cdq                 
            //   83e23f               | and                 edx, 0x3f
            //   03c2                 | add                 eax, edx

        $sequence_14 = { 0f1145f0 85d2 7e2a 8bce 81e107000080 7905 }
            // n = 6, score = 400
            //   0f1145f0             | movups              xmmword ptr [ebp - 0x10], xmm0
            //   85d2                 | test                edx, edx
            //   7e2a                 | jle                 0x2c
            //   8bce                 | mov                 ecx, esi
            //   81e107000080         | and                 ecx, 0x80000007
            //   7905                 | jns                 7

        $sequence_15 = { a3???????? 51 c745e453686c77 c745e861706900 ffd0 }
            // n = 5, score = 400
            //   a3????????           |                     
            //   51                   | push                ecx
            //   c745e453686c77       | mov                 dword ptr [ebp - 0x1c], 0x776c6853
            //   c745e861706900       | mov                 dword ptr [ebp - 0x18], 0x697061
            //   ffd0                 | call                eax

        $sequence_16 = { 6a00 53 ff75dc ff15???????? ff75dc 85c0 }
            // n = 6, score = 400
            //   6a00                 | push                0
            //   53                   | push                ebx
            //   ff75dc               | push                dword ptr [ebp - 0x24]
            //   ff15????????         |                     
            //   ff75dc               | push                dword ptr [ebp - 0x24]
            //   85c0                 | test                eax, eax

        $sequence_17 = { e9???????? bbfeffffff eb05 bbfdffffff }
            // n = 4, score = 400
            //   e9????????           |                     
            //   bbfeffffff           | mov                 ebx, 0xfffffffe
            //   eb05                 | jmp                 7
            //   bbfdffffff           | mov                 ebx, 0xfffffffd

        $sequence_18 = { 84c0 75f0 8d55ec c745ec5c417070 c745f06c655c55 8bf2 }
            // n = 6, score = 400
            //   84c0                 | test                al, al
            //   75f0                 | jne                 0xfffffff2
            //   8d55ec               | lea                 edx, dword ptr [ebp - 0x14]
            //   c745ec5c417070       | mov                 dword ptr [ebp - 0x14], 0x7070415c
            //   c745f06c655c55       | mov                 dword ptr [ebp - 0x10], 0x555c656c
            //   8bf2                 | mov                 esi, edx

        $sequence_19 = { 0f2805???????? 57 8bf9 0f1145f0 85d2 }
            // n = 5, score = 400
            //   0f2805????????       |                     
            //   57                   | push                edi
            //   8bf9                 | mov                 edi, ecx
            //   0f1145f0             | movups              xmmword ptr [ebp - 0x10], xmm0
            //   85d2                 | test                edx, edx

        $sequence_20 = { 24a0 3ca0 7518 b800080000 }
            // n = 4, score = 400
            //   24a0                 | and                 al, 0xa0
            //   3ca0                 | cmp                 al, 0xa0
            //   7518                 | jne                 0x1a
            //   b800080000           | mov                 eax, 0x800

        $sequence_21 = { c1e810 884106 8bc2 c1e808 884107 }
            // n = 5, score = 400
            //   c1e810               | shr                 eax, 0x10
            //   884106               | mov                 byte ptr [ecx + 6], al
            //   8bc2                 | mov                 eax, edx
            //   c1e808               | shr                 eax, 8
            //   884107               | mov                 byte ptr [ecx + 7], al

        $sequence_22 = { e8???????? 85c0 790b b883ffffff }
            // n = 4, score = 400
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   790b                 | jns                 0xd
            //   b883ffffff           | mov                 eax, 0xffffff83

        $sequence_23 = { e8???????? 85c0 755e 83ff20 }
            // n = 4, score = 400
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   755e                 | jne                 0x60
            //   83ff20               | cmp                 edi, 0x20

    condition:
        7 of them and filesize < 2170880
}