rule win_locky_decryptor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.locky_decryptor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.locky_decryptor"
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
        $sequence_0 = { 50 53 ff75f4 66a5 ff55f0 85c0 740b }
            // n = 7, score = 100
            //   50                   | push                eax
            //   53                   | push                ebx
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   66a5                 | movsw               word ptr es:[edi], word ptr [esi]
            //   ff55f0               | call                dword ptr [ebp - 0x10]
            //   85c0                 | test                eax, eax
            //   740b                 | je                  0xd

        $sequence_1 = { e9???????? 8b4508 83c004 e9???????? b8???????? e9???????? 8d8558ffffff }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83c004               | add                 eax, 4
            //   e9????????           |                     
            //   b8????????           |                     
            //   e9????????           |                     
            //   8d8558ffffff         | lea                 eax, [ebp - 0xa8]

        $sequence_2 = { 0f8f66ffffff 33db 33c0 c744244007000000 895c243c 668944242c c684248c00000002 }
            // n = 7, score = 100
            //   0f8f66ffffff         | jg                  0xffffff6c
            //   33db                 | xor                 ebx, ebx
            //   33c0                 | xor                 eax, eax
            //   c744244007000000     | mov                 dword ptr [esp + 0x40], 7
            //   895c243c             | mov                 dword ptr [esp + 0x3c], ebx
            //   668944242c           | mov                 word ptr [esp + 0x2c], ax
            //   c684248c00000002     | mov                 byte ptr [esp + 0x8c], 2

        $sequence_3 = { 3945ec 7530 395ddc 7413 837de008 8b45cc 7303 }
            // n = 7, score = 100
            //   3945ec               | cmp                 dword ptr [ebp - 0x14], eax
            //   7530                 | jne                 0x32
            //   395ddc               | cmp                 dword ptr [ebp - 0x24], ebx
            //   7413                 | je                  0x15
            //   837de008             | cmp                 dword ptr [ebp - 0x20], 8
            //   8b45cc               | mov                 eax, dword ptr [ebp - 0x34]
            //   7303                 | jae                 5

        $sequence_4 = { 53 ff75f4 ff55f8 85c0 }
            // n = 4, score = 100
            //   53                   | push                ebx
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   ff55f8               | call                dword ptr [ebp - 8]
            //   85c0                 | test                eax, eax

        $sequence_5 = { 8b8d6cffffff 7306 8d8d6cffffff 6a5f 5a }
            // n = 5, score = 100
            //   8b8d6cffffff         | mov                 ecx, dword ptr [ebp - 0x94]
            //   7306                 | jae                 8
            //   8d8d6cffffff         | lea                 ecx, [ebp - 0x94]
            //   6a5f                 | push                0x5f
            //   5a                   | pop                 edx

        $sequence_6 = { 8d851cfeffff 50 8d45ec e8???????? 8d45ec e8???????? 395dec }
            // n = 7, score = 100
            //   8d851cfeffff         | lea                 eax, [ebp - 0x1e4]
            //   50                   | push                eax
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   e8????????           |                     
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   e8????????           |                     
            //   395dec               | cmp                 dword ptr [ebp - 0x14], ebx

        $sequence_7 = { 7450 83bd54ffffff06 7247 e8???????? 85c0 743e 56 }
            // n = 7, score = 100
            //   7450                 | je                  0x52
            //   83bd54ffffff06       | cmp                 dword ptr [ebp - 0xac], 6
            //   7247                 | jb                  0x49
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   743e                 | je                  0x40
            //   56                   | push                esi

        $sequence_8 = { 8bc8 894db8 6830020000 8d950cfcffff c645fc04 8b01 }
            // n = 6, score = 100
            //   8bc8                 | mov                 ecx, eax
            //   894db8               | mov                 dword ptr [ebp - 0x48], ecx
            //   6830020000           | push                0x230
            //   8d950cfcffff         | lea                 edx, [ebp - 0x3f4]
            //   c645fc04             | mov                 byte ptr [ebp - 4], 4
            //   8b01                 | mov                 eax, dword ptr [ecx]

        $sequence_9 = { ff750c 8d742414 e8???????? 8364244c00 }
            // n = 4, score = 100
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   8d742414             | lea                 esi, [esp + 0x14]
            //   e8????????           |                     
            //   8364244c00           | and                 dword ptr [esp + 0x4c], 0

    condition:
        7 of them and filesize < 278528
}