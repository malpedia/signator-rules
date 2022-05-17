rule win_stuxnet_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.stuxnet."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stuxnet"
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
        $sequence_0 = { e8???????? 33ff 59 59 3bdf 7410 3bde }
            // n = 7, score = 200
            //   e8????????           |                     
            //   33ff                 | xor                 edi, edi
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   3bdf                 | cmp                 ebx, edi
            //   7410                 | je                  0x12
            //   3bde                 | cmp                 ebx, esi

        $sequence_1 = { ff7510 8d4df4 e8???????? 33db 395d08 752e e8???????? }
            // n = 7, score = 200
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   8d4df4               | lea                 ecx, [ebp - 0xc]
            //   e8????????           |                     
            //   33db                 | xor                 ebx, ebx
            //   395d08               | cmp                 dword ptr [ebp + 8], ebx
            //   752e                 | jne                 0x30
            //   e8????????           |                     

        $sequence_2 = { e8???????? c3 8d75c4 e9???????? 8b45ec e9???????? 8d75a8 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   c3                   | ret                 
            //   8d75c4               | lea                 esi, [ebp - 0x3c]
            //   e9????????           |                     
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   e9????????           |                     
            //   8d75a8               | lea                 esi, [ebp - 0x58]

        $sequence_3 = { e8???????? 8975f0 c645fc00 8d4db4 e8???????? 8b4df4 8b4508 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8975f0               | mov                 dword ptr [ebp - 0x10], esi
            //   c645fc00             | mov                 byte ptr [ebp - 4], 0
            //   8d4db4               | lea                 ecx, [ebp - 0x4c]
            //   e8????????           |                     
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_4 = { e8???????? c684245401000007 8d44242c 50 e8???????? c684245401000008 6a00 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   c684245401000007     | mov                 byte ptr [esp + 0x154], 7
            //   8d44242c             | lea                 eax, [esp + 0x2c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   c684245401000008     | mov                 byte ptr [esp + 0x154], 8
            //   6a00                 | push                0

        $sequence_5 = { e8???????? ff75c8 8d45ec 50 e8???????? ff75c9 8d45ec }
            // n = 7, score = 200
            //   e8????????           |                     
            //   ff75c8               | push                dword ptr [ebp - 0x38]
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   50                   | push                eax
            //   e8????????           |                     
            //   ff75c9               | push                dword ptr [ebp - 0x37]
            //   8d45ec               | lea                 eax, [ebp - 0x14]

        $sequence_6 = { a5 a5 ff4d0c 8345080c ebe4 834dfcff 8b4df4 }
            // n = 7, score = 200
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   ff4d0c               | dec                 dword ptr [ebp + 0xc]
            //   8345080c             | add                 dword ptr [ebp + 8], 0xc
            //   ebe4                 | jmp                 0xffffffe6
            //   834dfcff             | or                  dword ptr [ebp - 4], 0xffffffff
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_7 = { c745f001000000 7205 8b7610 eb03 83c610 ff750c 56 }
            // n = 7, score = 200
            //   c745f001000000       | mov                 dword ptr [ebp - 0x10], 1
            //   7205                 | jb                  7
            //   8b7610               | mov                 esi, dword ptr [esi + 0x10]
            //   eb03                 | jmp                 5
            //   83c610               | add                 esi, 0x10
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   56                   | push                esi

        $sequence_8 = { 745c c745ec03000000 c645fc01 50 8b4d08 e8???????? 8945ec }
            // n = 7, score = 200
            //   745c                 | je                  0x5e
            //   c745ec03000000       | mov                 dword ptr [ebp - 0x14], 3
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   50                   | push                eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   e8????????           |                     
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax

        $sequence_9 = { c9 c3 885dfc 8d4de4 e8???????? b001 ebe2 }
            // n = 7, score = 200
            //   c9                   | leave               
            //   c3                   | ret                 
            //   885dfc               | mov                 byte ptr [ebp - 4], bl
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]
            //   e8????????           |                     
            //   b001                 | mov                 al, 1
            //   ebe2                 | jmp                 0xffffffe4

    condition:
        7 of them and filesize < 2495488
}