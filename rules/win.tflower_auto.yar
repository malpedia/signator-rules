rule win_tflower_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.tflower."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tflower"
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
        $sequence_0 = { 03148d20bd4e00 8b4e6c c1e818 c1eb10 33148520c14e00 0fb6c3 }
            // n = 6, score = 200
            //   03148d20bd4e00       | add                 edx, dword ptr [ecx*4 + 0x4ebd20]
            //   8b4e6c               | mov                 ecx, dword ptr [esi + 0x6c]
            //   c1e818               | shr                 eax, 0x18
            //   c1eb10               | shr                 ebx, 0x10
            //   33148520c14e00       | xor                 edx, dword ptr [eax*4 + 0x4ec120]
            //   0fb6c3               | movzx               eax, bl

        $sequence_1 = { 0001 7708 00f3 7608 }
            // n = 4, score = 200
            //   0001                 | add                 byte ptr [ecx], al
            //   7708                 | ja                  0xa
            //   00f3                 | add                 bl, dh
            //   7608                 | jbe                 0xa

        $sequence_2 = { 0001 0200 0103 0303 }
            // n = 4, score = 200
            //   0001                 | add                 byte ptr [ecx], al
            //   0200                 | add                 al, byte ptr [eax]
            //   0103                 | add                 dword ptr [ebx], eax
            //   0303                 | add                 eax, dword ptr [ebx]

        $sequence_3 = { c1f806 83e13f 6bc930 8b048578515000 80640828fe ff36 }
            // n = 6, score = 200
            //   c1f806               | sar                 eax, 6
            //   83e13f               | and                 ecx, 0x3f
            //   6bc930               | imul                ecx, ecx, 0x30
            //   8b048578515000       | mov                 eax, dword ptr [eax*4 + 0x505178]
            //   80640828fe           | and                 byte ptr [eax + ecx + 0x28], 0xfe
            //   ff36                 | push                dword ptr [esi]

        $sequence_4 = { 331cad20cd4e00 331c8520d54e00 335c2418 33d9 33da 8bc3 }
            // n = 6, score = 200
            //   331cad20cd4e00       | xor                 ebx, dword ptr [ebp*4 + 0x4ecd20]
            //   331c8520d54e00       | xor                 ebx, dword ptr [eax*4 + 0x4ed520]
            //   335c2418             | xor                 ebx, dword ptr [esp + 0x18]
            //   33d9                 | xor                 ebx, ecx
            //   33da                 | xor                 ebx, edx
            //   8bc3                 | mov                 eax, ebx

        $sequence_5 = { 001a 0c05 003c0c 05004e0c05 }
            // n = 4, score = 200
            //   001a                 | add                 byte ptr [edx], bl
            //   0c05                 | or                  al, 5
            //   003c0c               | add                 byte ptr [esp + ecx], bh
            //   05004e0c05           | add                 eax, 0x50c4e00

        $sequence_6 = { 000f 7708 0001 7708 }
            // n = 4, score = 200
            //   000f                 | add                 byte ptr [edi], cl
            //   7708                 | ja                  0xa
            //   0001                 | add                 byte ptr [ecx], al
            //   7708                 | ja                  0xa

        $sequence_7 = { 7d4d 8b049d78515000 8945d8 85c0 7553 e8???????? }
            // n = 6, score = 200
            //   7d4d                 | jge                 0x4f
            //   8b049d78515000       | mov                 eax, dword ptr [ebx*4 + 0x505178]
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   85c0                 | test                eax, eax
            //   7553                 | jne                 0x55
            //   e8????????           |                     

        $sequence_8 = { 33b9466f4f00 33b14a6f4f00 8b4c241c 0facca18 c1e918 }
            // n = 5, score = 200
            //   33b9466f4f00         | xor                 edi, dword ptr [ecx + 0x4f6f46]
            //   33b14a6f4f00         | xor                 esi, dword ptr [ecx + 0x4f6f4a]
            //   8b4c241c             | mov                 ecx, dword ptr [esp + 0x1c]
            //   0facca18             | shrd                edx, ecx, 0x18
            //   c1e918               | shr                 ecx, 0x18

        $sequence_9 = { 0010 740b 0021 740b }
            // n = 4, score = 200
            //   0010                 | add                 byte ptr [eax], dl
            //   740b                 | je                  0xd
            //   0021                 | add                 byte ptr [ecx], ah
            //   740b                 | je                  0xd

        $sequence_10 = { 0fb6c3 8b5d78 2b148520c54e00 33f2 03de d3c3 }
            // n = 6, score = 200
            //   0fb6c3               | movzx               eax, bl
            //   8b5d78               | mov                 ebx, dword ptr [ebp + 0x78]
            //   2b148520c54e00       | sub                 edx, dword ptr [eax*4 + 0x4ec520]
            //   33f2                 | xor                 esi, edx
            //   03de                 | add                 ebx, esi
            //   d3c3                 | rol                 ebx, cl

        $sequence_11 = { eb5c 8b8d9cfdfcff 8d95d0fdfcff e8???????? }
            // n = 4, score = 200
            //   eb5c                 | jmp                 0x5e
            //   8b8d9cfdfcff         | mov                 ecx, dword ptr [ebp - 0x30264]
            //   8d95d0fdfcff         | lea                 edx, dword ptr [ebp - 0x30230]
            //   e8????????           |                     

        $sequence_12 = { 0008 7408 0002 7408 }
            // n = 4, score = 200
            //   0008                 | add                 byte ptr [eax], cl
            //   7408                 | je                  0xa
            //   0002                 | add                 byte ptr [edx], al
            //   7408                 | je                  0xa

        $sequence_13 = { 0002 7408 00f7 7308 }
            // n = 4, score = 200
            //   0002                 | add                 byte ptr [edx], al
            //   7408                 | je                  0xa
            //   00f7                 | add                 bh, dh
            //   7308                 | jae                 0xa

        $sequence_14 = { 000b 8605???????? 007885 0500788605 }
            // n = 4, score = 200
            //   000b                 | add                 byte ptr [ebx], cl
            //   8605????????         |                     
            //   007885               | add                 byte ptr [eax - 0x7b], bh
            //   0500788605           | add                 eax, 0x5867800

        $sequence_15 = { 83f807 773d ff2485fce94600 4e 8bc2 }
            // n = 5, score = 200
            //   83f807               | cmp                 eax, 7
            //   773d                 | ja                  0x3f
            //   ff2485fce94600       | jmp                 dword ptr [eax*4 + 0x46e9fc]
            //   4e                   | dec                 esi
            //   8bc2                 | mov                 eax, edx

    condition:
        7 of them and filesize < 6578176
}