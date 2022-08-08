rule win_xiaoba_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-08-05"
        version = "1"
        description = "Detects win.xiaoba."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xiaoba"
        malpedia_rule_date = "20220805"
        malpedia_hash = "6ec06c64bcfdbeda64eff021c766b4ce34542b71"
        malpedia_version = "20220808"
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
        $sequence_0 = { 897364 897360 e9???????? 3bc6 7534 8d3cad00000000 57 }
            // n = 7, score = 100
            //   897364               | mov                 dword ptr [ebx + 0x64], esi
            //   897360               | mov                 dword ptr [ebx + 0x60], esi
            //   e9????????           |                     
            //   3bc6                 | cmp                 eax, esi
            //   7534                 | jne                 0x36
            //   8d3cad00000000       | lea                 edi, [ebp*4]
            //   57                   | push                edi

        $sequence_1 = { 52 57 e8???????? 8b07 83c408 8bce 6a01 }
            // n = 7, score = 100
            //   52                   | push                edx
            //   57                   | push                edi
            //   e8????????           |                     
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   83c408               | add                 esp, 8
            //   8bce                 | mov                 ecx, esi
            //   6a01                 | push                1

        $sequence_2 = { ff75fc b804000000 e8???????? 3965e8 740d 6806000000 e8???????? }
            // n = 7, score = 100
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   b804000000           | mov                 eax, 4
            //   e8????????           |                     
            //   3965e8               | cmp                 dword ptr [ebp - 0x18], esp
            //   740d                 | je                  0xf
            //   6806000000           | push                6
            //   e8????????           |                     

        $sequence_3 = { e8???????? 8b442448 8b4c2444 40 41 50 51 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b442448             | mov                 eax, dword ptr [esp + 0x48]
            //   8b4c2444             | mov                 ecx, dword ptr [esp + 0x44]
            //   40                   | inc                 eax
            //   41                   | inc                 ecx
            //   50                   | push                eax
            //   51                   | push                ecx

        $sequence_4 = { 8b542470 8b4c2414 8b742468 3bde 7d2b 2bf3 2bcf }
            // n = 7, score = 100
            //   8b542470             | mov                 edx, dword ptr [esp + 0x70]
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   8b742468             | mov                 esi, dword ptr [esp + 0x68]
            //   3bde                 | cmp                 ebx, esi
            //   7d2b                 | jge                 0x2d
            //   2bf3                 | sub                 esi, ebx
            //   2bcf                 | sub                 ecx, edi

        $sequence_5 = { 55 6a00 6a00 51 89442434 ff15???????? 8b54241c }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   89442434             | mov                 dword ptr [esp + 0x34], eax
            //   ff15????????         |                     
            //   8b54241c             | mov                 edx, dword ptr [esp + 0x1c]

        $sequence_6 = { 0fafc3 33db 668b1c5500a55f00 33d2 0fafd9 03c3 8b5c242c }
            // n = 7, score = 100
            //   0fafc3               | imul                eax, ebx
            //   33db                 | xor                 ebx, ebx
            //   668b1c5500a55f00     | mov                 bx, word ptr [edx*2 + 0x5fa500]
            //   33d2                 | xor                 edx, edx
            //   0fafd9               | imul                ebx, ecx
            //   03c3                 | add                 eax, ebx
            //   8b5c242c             | mov                 ebx, dword ptr [esp + 0x2c]

        $sequence_7 = { 6804000000 bb???????? e8???????? 83c434 8945ec 58 }
            // n = 6, score = 100
            //   6804000000           | push                4
            //   bb????????           |                     
            //   e8????????           |                     
            //   83c434               | add                 esp, 0x34
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   58                   | pop                 eax

        $sequence_8 = { 83c404 8986dc000000 50 ff15???????? 50 8d8ef8000000 e8???????? }
            // n = 7, score = 100
            //   83c404               | add                 esp, 4
            //   8986dc000000         | mov                 dword ptr [esi + 0xdc], eax
            //   50                   | push                eax
            //   ff15????????         |                     
            //   50                   | push                eax
            //   8d8ef8000000         | lea                 ecx, [esi + 0xf8]
            //   e8????????           |                     

        $sequence_9 = { 8b148d98c05f00 8b4b0c c1ef03 890491 8b5308 42 895308 }
            // n = 7, score = 100
            //   8b148d98c05f00       | mov                 edx, dword ptr [ecx*4 + 0x5fc098]
            //   8b4b0c               | mov                 ecx, dword ptr [ebx + 0xc]
            //   c1ef03               | shr                 edi, 3
            //   890491               | mov                 dword ptr [ecx + edx*4], eax
            //   8b5308               | mov                 edx, dword ptr [ebx + 8]
            //   42                   | inc                 edx
            //   895308               | mov                 dword ptr [ebx + 8], edx

    condition:
        7 of them and filesize < 5177344
}