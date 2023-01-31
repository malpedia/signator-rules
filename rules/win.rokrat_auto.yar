rule win_rokrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.rokrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rokrat"
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
        $sequence_0 = { 83ec18 c645fc02 8bcc 8d9640010000 c7411407000000 c7411000000000 83791408 }
            // n = 7, score = 300
            //   83ec18               | sub                 esp, 0x18
            //   c645fc02             | mov                 byte ptr [ebp - 4], 2
            //   8bcc                 | mov                 ecx, esp
            //   8d9640010000         | lea                 edx, [esi + 0x140]
            //   c7411407000000       | mov                 dword ptr [ecx + 0x14], 7
            //   c7411000000000       | mov                 dword ptr [ecx + 0x10], 0
            //   83791408             | cmp                 dword ptr [ecx + 0x14], 8

        $sequence_1 = { 6a01 89442410 ffd6 6a00 }
            // n = 4, score = 300
            //   6a01                 | push                1
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   ffd6                 | call                esi
            //   6a00                 | push                0

        $sequence_2 = { 50 ff15???????? e8???????? 40 }
            // n = 4, score = 300
            //   50                   | push                eax
            //   ff15????????         |                     
            //   e8????????           |                     
            //   40                   | inc                 eax

        $sequence_3 = { 0f1005???????? 8d85c0fdffff c785c0fdffff32000000 c785d8fdffff01000000 }
            // n = 4, score = 300
            //   0f1005????????       |                     
            //   8d85c0fdffff         | lea                 eax, [ebp - 0x240]
            //   c785c0fdffff32000000     | mov    dword ptr [ebp - 0x240], 0x32
            //   c785d8fdffff01000000     | mov    dword ptr [ebp - 0x228], 1

        $sequence_4 = { 50 6a00 56 e8???????? 5f 8bc6 }
            // n = 6, score = 300
            //   50                   | push                eax
            //   6a00                 | push                0
            //   56                   | push                esi
            //   e8????????           |                     
            //   5f                   | pop                 edi
            //   8bc6                 | mov                 eax, esi

        $sequence_5 = { 894dfc 8b4310 8b7e10 40 c745f001000000 3bf8 }
            // n = 6, score = 300
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8b4310               | mov                 eax, dword ptr [ebx + 0x10]
            //   8b7e10               | mov                 edi, dword ptr [esi + 0x10]
            //   40                   | inc                 eax
            //   c745f001000000       | mov                 dword ptr [ebp - 0x10], 1
            //   3bf8                 | cmp                 edi, eax

        $sequence_6 = { 7419 c70600000000 c7460400000000 c7460800000000 }
            // n = 4, score = 300
            //   7419                 | je                  0x1b
            //   c70600000000         | mov                 dword ptr [esi], 0
            //   c7460400000000       | mov                 dword ptr [esi + 4], 0
            //   c7460800000000       | mov                 dword ptr [esi + 8], 0

        $sequence_7 = { 752f e8???????? 8b45e8 8d48ff 3bc1 }
            // n = 5, score = 300
            //   752f                 | jne                 0x31
            //   e8????????           |                     
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   8d48ff               | lea                 ecx, [eax - 1]
            //   3bc1                 | cmp                 eax, ecx

        $sequence_8 = { 68???????? 668910 e8???????? 83ec18 c745fc00000000 8bcc 8965ec }
            // n = 7, score = 300
            //   68????????           |                     
            //   668910               | mov                 word ptr [eax], dx
            //   e8????????           |                     
            //   83ec18               | sub                 esp, 0x18
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   8bcc                 | mov                 ecx, esp
            //   8965ec               | mov                 dword ptr [ebp - 0x14], esp

        $sequence_9 = { ff15???????? 83c404 33c0 898520040000 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4
            //   33c0                 | xor                 eax, eax
            //   898520040000         | mov                 dword ptr [ebp + 0x420], eax

        $sequence_10 = { ff15???????? 83c404 5e 8bc7 5f 5d 5b }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4
            //   5e                   | pop                 esi
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx

        $sequence_11 = { ff15???????? 83c404 5e 5d 5f b81b000000 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   5f                   | pop                 edi
            //   b81b000000           | mov                 eax, 0x1b

        $sequence_12 = { ff15???????? 83c404 33c9 85c0 0f95c1 8986f8860000 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4
            //   33c9                 | xor                 ecx, ecx
            //   85c0                 | test                eax, eax
            //   0f95c1               | setne               cl
            //   8986f8860000         | mov                 dword ptr [esi + 0x86f8], eax

        $sequence_13 = { ff15???????? 83c404 399d5c040000 742a }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4
            //   399d5c040000         | cmp                 dword ptr [ebp + 0x45c], ebx
            //   742a                 | je                  0x2c

        $sequence_14 = { ff15???????? 83c404 395c241c 7428 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4
            //   395c241c             | cmp                 dword ptr [esp + 0x1c], ebx
            //   7428                 | je                  0x2a

        $sequence_15 = { ff15???????? 83c404 396c2418 0f8435020000 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4
            //   396c2418             | cmp                 dword ptr [esp + 0x18], ebp
            //   0f8435020000         | je                  0x23b

    condition:
        7 of them and filesize < 2932736
}