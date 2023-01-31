rule win_waterspout_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.waterspout."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.waterspout"
        malpedia_rule_date = "20230124"
        malpedia_hash = "2ee0eebba83dce3d019a90519f2f972c0fcf9686"
        malpedia_version = "20230125"
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
        $sequence_0 = { 8b44240c 53 56 8b742410 57 3bd6 7412 }
            // n = 7, score = 200
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8b742410             | mov                 esi, dword ptr [esp + 0x10]
            //   57                   | push                edi
            //   3bd6                 | cmp                 edx, esi
            //   7412                 | je                  0x14

        $sequence_1 = { 8d44241c 8b11 8bce 52 6a00 50 }
            // n = 6, score = 200
            //   8d44241c             | lea                 eax, [esp + 0x1c]
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   8bce                 | mov                 ecx, esi
            //   52                   | push                edx
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_2 = { c68424430100004e c684244401000008 c68424450100002e c6842446010000a1 c684244701000066 c684244801000028 c6842449010000d9 }
            // n = 7, score = 200
            //   c68424430100004e     | mov                 byte ptr [esp + 0x143], 0x4e
            //   c684244401000008     | mov                 byte ptr [esp + 0x144], 8
            //   c68424450100002e     | mov                 byte ptr [esp + 0x145], 0x2e
            //   c6842446010000a1     | mov                 byte ptr [esp + 0x146], 0xa1
            //   c684244701000066     | mov                 byte ptr [esp + 0x147], 0x66
            //   c684244801000028     | mov                 byte ptr [esp + 0x148], 0x28
            //   c6842449010000d9     | mov                 byte ptr [esp + 0x149], 0xd9

        $sequence_3 = { 56 0fbe44242c 03ca 8ae0 8801 8d4c2418 ff15???????? }
            // n = 7, score = 200
            //   56                   | push                esi
            //   0fbe44242c           | movsx               eax, byte ptr [esp + 0x2c]
            //   03ca                 | add                 ecx, edx
            //   8ae0                 | mov                 ah, al
            //   8801                 | mov                 byte ptr [ecx], al
            //   8d4c2418             | lea                 ecx, [esp + 0x18]
            //   ff15????????         |                     

        $sequence_4 = { c3 83f801 7563 81fe00040000 7704 8bee 7514 }
            // n = 7, score = 200
            //   c3                   | ret                 
            //   83f801               | cmp                 eax, 1
            //   7563                 | jne                 0x65
            //   81fe00040000         | cmp                 esi, 0x400
            //   7704                 | ja                  6
            //   8bee                 | mov                 ebp, esi
            //   7514                 | jne                 0x16

        $sequence_5 = { c644242001 8b54241c 52 ff15???????? 8b442420 5d 5f }
            // n = 7, score = 200
            //   c644242001           | mov                 byte ptr [esp + 0x20], 1
            //   8b54241c             | mov                 edx, dword ptr [esp + 0x1c]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   5d                   | pop                 ebp
            //   5f                   | pop                 edi

        $sequence_6 = { 7503 55 eb01 53 56 e8???????? }
            // n = 6, score = 200
            //   7503                 | jne                 5
            //   55                   | push                ebp
            //   eb01                 | jmp                 3
            //   53                   | push                ebx
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_7 = { ba01000000 8d7801 896c241c 8d4c2414 8bc7 be04000000 8a18 }
            // n = 7, score = 200
            //   ba01000000           | mov                 edx, 1
            //   8d7801               | lea                 edi, [eax + 1]
            //   896c241c             | mov                 dword ptr [esp + 0x1c], ebp
            //   8d4c2414             | lea                 ecx, [esp + 0x14]
            //   8bc7                 | mov                 eax, edi
            //   be04000000           | mov                 esi, 4
            //   8a18                 | mov                 bl, byte ptr [eax]

        $sequence_8 = { 0bc7 8a4c042c 51 6a01 8d4c2424 ff15???????? 83e63f }
            // n = 7, score = 200
            //   0bc7                 | or                  eax, edi
            //   8a4c042c             | mov                 cl, byte ptr [esp + eax + 0x2c]
            //   51                   | push                ecx
            //   6a01                 | push                1
            //   8d4c2424             | lea                 ecx, [esp + 0x24]
            //   ff15????????         |                     
            //   83e63f               | and                 esi, 0x3f

        $sequence_9 = { 88442415 51 e8???????? 8a4e02 8a5603 32c1 8a0e }
            // n = 7, score = 200
            //   88442415             | mov                 byte ptr [esp + 0x15], al
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8a4e02               | mov                 cl, byte ptr [esi + 2]
            //   8a5603               | mov                 dl, byte ptr [esi + 3]
            //   32c1                 | xor                 al, cl
            //   8a0e                 | mov                 cl, byte ptr [esi]

    condition:
        7 of them and filesize < 98304
}