rule win_icefog_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.icefog."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.icefog"
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
        $sequence_0 = { 8b45ac 3b8574ffffff 0f8dcb000000 8b4485dc 8b55a4 8bc8 898570ffffff }
            // n = 7, score = 200
            //   8b45ac               | mov                 eax, dword ptr [ebp - 0x54]
            //   3b8574ffffff         | cmp                 eax, dword ptr [ebp - 0x8c]
            //   0f8dcb000000         | jge                 0xd1
            //   8b4485dc             | mov                 eax, dword ptr [ebp + eax*4 - 0x24]
            //   8b55a4               | mov                 edx, dword ptr [ebp - 0x5c]
            //   8bc8                 | mov                 ecx, eax
            //   898570ffffff         | mov                 dword ptr [ebp - 0x90], eax

        $sequence_1 = { 898df0feffff c785f4feffff00000000 7527 85db 740f 68???????? e8???????? }
            // n = 7, score = 200
            //   898df0feffff         | mov                 dword ptr [ebp - 0x110], ecx
            //   c785f4feffff00000000     | mov    dword ptr [ebp - 0x10c], 0
            //   7527                 | jne                 0x29
            //   85db                 | test                ebx, ebx
            //   740f                 | je                  0x11
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_2 = { 818d40ffffff00000002 8b8d10ffffff dd4110 dd8538ffffff d8d1 dfe0 ddd9 }
            // n = 7, score = 200
            //   818d40ffffff00000002     | or    dword ptr [ebp - 0xc0], 0x2000000
            //   8b8d10ffffff         | mov                 ecx, dword ptr [ebp - 0xf0]
            //   dd4110               | fld                 qword ptr [ecx + 0x10]
            //   dd8538ffffff         | fld                 qword ptr [ebp - 0xc8]
            //   d8d1                 | fcom                st(1)
            //   dfe0                 | fnstsw              ax
            //   ddd9                 | fstp                st(1)

        $sequence_3 = { 8b45a4 8b4848 8b4648 51 6a05 8bca e8???????? }
            // n = 7, score = 200
            //   8b45a4               | mov                 eax, dword ptr [ebp - 0x5c]
            //   8b4848               | mov                 ecx, dword ptr [eax + 0x48]
            //   8b4648               | mov                 eax, dword ptr [esi + 0x48]
            //   51                   | push                ecx
            //   6a05                 | push                5
            //   8bca                 | mov                 ecx, edx
            //   e8????????           |                     

        $sequence_4 = { 1bd3 eb5f 53 51 52 50 e8???????? }
            // n = 7, score = 200
            //   1bd3                 | sbb                 edx, ebx
            //   eb5f                 | jmp                 0x61
            //   53                   | push                ebx
            //   51                   | push                ecx
            //   52                   | push                edx
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_5 = { 8bd8 83c408 3bde 0f84dc0a0000 8b4b48 8b17 51 }
            // n = 7, score = 200
            //   8bd8                 | mov                 ebx, eax
            //   83c408               | add                 esp, 8
            //   3bde                 | cmp                 ebx, esi
            //   0f84dc0a0000         | je                  0xae2
            //   8b4b48               | mov                 ecx, dword ptr [ebx + 0x48]
            //   8b17                 | mov                 edx, dword ptr [edi]
            //   51                   | push                ecx

        $sequence_6 = { 51 52 8d5ea4 8d4694 53 50 57 }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   52                   | push                edx
            //   8d5ea4               | lea                 ebx, [esi - 0x5c]
            //   8d4694               | lea                 eax, [esi - 0x6c]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   57                   | push                edi

        $sequence_7 = { e8???????? 83c40c 8d8dd0fdffff 51 56 c785d0fdffff2c020000 ff15???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d8dd0fdffff         | lea                 ecx, [ebp - 0x230]
            //   51                   | push                ecx
            //   56                   | push                esi
            //   c785d0fdffff2c020000     | mov    dword ptr [ebp - 0x230], 0x22c
            //   ff15????????         |                     

        $sequence_8 = { 8be5 5d c3 6a09 8d55dc 68???????? 52 }
            // n = 7, score = 200
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   6a09                 | push                9
            //   8d55dc               | lea                 edx, [ebp - 0x24]
            //   68????????           |                     
            //   52                   | push                edx

        $sequence_9 = { 8945e0 8955e8 8b55fc 8d4638 8d3cbf 8945ec 8d049500000000 }
            // n = 7, score = 200
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   8955e8               | mov                 dword ptr [ebp - 0x18], edx
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8d4638               | lea                 eax, [esi + 0x38]
            //   8d3cbf               | lea                 edi, [edi + edi*4]
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8d049500000000       | lea                 eax, [edx*4]

    condition:
        7 of them and filesize < 1187840
}