rule win_moure_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.moure."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.moure"
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
        $sequence_0 = { 2bfe 5a 33fe 5f e8???????? 57 }
            // n = 6, score = 100
            //   2bfe                 | sub                 edi, esi
            //   5a                   | pop                 edx
            //   33fe                 | xor                 edi, esi
            //   5f                   | pop                 edi
            //   e8????????           |                     
            //   57                   | push                edi

        $sequence_1 = { f7d1 81c1f8ffffff 2be1 59 e8???????? }
            // n = 5, score = 100
            //   f7d1                 | not                 ecx
            //   81c1f8ffffff         | add                 ecx, 0xfffffff8
            //   2be1                 | sub                 esp, ecx
            //   59                   | pop                 ecx
            //   e8????????           |                     

        $sequence_2 = { eb0a 8b45fc a3???????? 33f6 8d4df8 e8???????? }
            // n = 6, score = 100
            //   eb0a                 | jmp                 0xc
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   a3????????           |                     
            //   33f6                 | xor                 esi, esi
            //   8d4df8               | lea                 ecx, [ebp - 8]
            //   e8????????           |                     

        $sequence_3 = { da8d2bcdc1c9 9b 59 c21000 }
            // n = 4, score = 100
            //   da8d2bcdc1c9         | fimul               dword ptr [ebp - 0x363e32d5]
            //   9b                   | wait                
            //   59                   | pop                 ecx
            //   c21000               | ret                 0x10

        $sequence_4 = { 6b866b8710cd44 7e10 cd44 5e 10a8b9b6bfbf }
            // n = 5, score = 100
            //   6b866b8710cd44       | imul                eax, dword ptr [esi - 0x32ef7895], 0x44
            //   7e10                 | jle                 0x12
            //   cd44                 | int                 0x44
            //   5e                   | pop                 esi
            //   10a8b9b6bfbf         | adc                 byte ptr [eax - 0x40404947], ch

        $sequence_5 = { a1???????? 3bc6 741a f6401c01 7414 80781905 }
            // n = 6, score = 100
            //   a1????????           |                     
            //   3bc6                 | cmp                 eax, esi
            //   741a                 | je                  0x1c
            //   f6401c01             | test                byte ptr [eax + 0x1c], 1
            //   7414                 | je                  0x16
            //   80781905             | cmp                 byte ptr [eax + 0x19], 5

        $sequence_6 = { c1ee2e 5e 8b12 50 48 8d4418e9 }
            // n = 6, score = 100
            //   c1ee2e               | shr                 esi, 0x2e
            //   5e                   | pop                 esi
            //   8b12                 | mov                 edx, dword ptr [edx]
            //   50                   | push                eax
            //   48                   | dec                 eax
            //   8d4418e9             | lea                 eax, [eax + ebx - 0x17]

        $sequence_7 = { e9???????? 83e811 746e 48 7460 48 48 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   83e811               | sub                 eax, 0x11
            //   746e                 | je                  0x70
            //   48                   | dec                 eax
            //   7460                 | je                  0x62
            //   48                   | dec                 eax
            //   48                   | dec                 eax

        $sequence_8 = { 57 c745fc00000000 57 54 e8???????? 008dd46fcd00 }
            // n = 6, score = 100
            //   57                   | push                edi
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   57                   | push                edi
            //   54                   | push                esp
            //   e8????????           |                     
            //   008dd46fcd00         | add                 byte ptr [ebp + 0xcd6fd4], cl

        $sequence_9 = { 56 00750c 8bf1 007508 e8???????? 8bd8 85db }
            // n = 7, score = 100
            //   56                   | push                esi
            //   00750c               | add                 byte ptr [ebp + 0xc], dh
            //   8bf1                 | mov                 esi, ecx
            //   007508               | add                 byte ptr [ebp + 8], dh
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   85db                 | test                ebx, ebx

    condition:
        7 of them and filesize < 188416
}