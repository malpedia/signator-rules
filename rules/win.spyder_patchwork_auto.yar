rule win_spyder_patchwork_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.spyder_patchwork."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.spyder_patchwork"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
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
        $sequence_0 = { 2bc2 50 52 51 68???????? 6a02 e8???????? }
            // n = 7, score = 100
            //   2bc2                 | sub                 eax, edx
            //   50                   | push                eax
            //   52                   | push                edx
            //   51                   | push                ecx
            //   68????????           |                     
            //   6a02                 | push                2
            //   e8????????           |                     

        $sequence_1 = { 7e23 8b37 8bce 8b542420 c1e10a 03d1 8b8a00040000 }
            // n = 7, score = 100
            //   7e23                 | jle                 0x25
            //   8b37                 | mov                 esi, dword ptr [edi]
            //   8bce                 | mov                 ecx, esi
            //   8b542420             | mov                 edx, dword ptr [esp + 0x20]
            //   c1e10a               | shl                 ecx, 0xa
            //   03d1                 | add                 edx, ecx
            //   8b8a00040000         | mov                 ecx, dword ptr [edx + 0x400]

        $sequence_2 = { 7409 b9f7ff0000 66214f0c 6800010000 57 56 e8???????? }
            // n = 7, score = 100
            //   7409                 | je                  0xb
            //   b9f7ff0000           | mov                 ecx, 0xfff7
            //   66214f0c             | and                 word ptr [edi + 0xc], cx
            //   6800010000           | push                0x100
            //   57                   | push                edi
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_3 = { c3 33c0 84db 56 0f95c0 03c7 50 }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   33c0                 | xor                 eax, eax
            //   84db                 | test                bl, bl
            //   56                   | push                esi
            //   0f95c0               | setne               al
            //   03c7                 | add                 eax, edi
            //   50                   | push                eax

        $sequence_4 = { 89040e b001 5e 5b c3 8bff 53 }
            // n = 7, score = 100
            //   89040e               | mov                 dword ptr [esi + ecx], eax
            //   b001                 | mov                 al, 1
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   8bff                 | mov                 edi, edi
            //   53                   | push                ebx

        $sequence_5 = { 8ae3 8d142e c0e404 b90f000000 83ee10 8ac4 8d52ff }
            // n = 7, score = 100
            //   8ae3                 | mov                 ah, bl
            //   8d142e               | lea                 edx, [esi + ebp]
            //   c0e404               | shl                 ah, 4
            //   b90f000000           | mov                 ecx, 0xf
            //   83ee10               | sub                 esi, 0x10
            //   8ac4                 | mov                 al, ah
            //   8d52ff               | lea                 edx, [edx - 1]

        $sequence_6 = { 8d0c50 d1fa 0fb601 8d3483 668b8648080000 668901 0393540c0000 }
            // n = 7, score = 100
            //   8d0c50               | lea                 ecx, [eax + edx*2]
            //   d1fa                 | sar                 edx, 1
            //   0fb601               | movzx               eax, byte ptr [ecx]
            //   8d3483               | lea                 esi, [ebx + eax*4]
            //   668b8648080000       | mov                 ax, word ptr [esi + 0x848]
            //   668901               | mov                 word ptr [ecx], ax
            //   0393540c0000         | add                 edx, dword ptr [ebx + 0xc54]

        $sequence_7 = { ff742430 e8???????? 83c410 8bc8 85d2 0f8c8f000000 7f08 }
            // n = 7, score = 100
            //   ff742430             | push                dword ptr [esp + 0x30]
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8bc8                 | mov                 ecx, eax
            //   85d2                 | test                edx, edx
            //   0f8c8f000000         | jl                  0x95
            //   7f08                 | jg                  0xa

        $sequence_8 = { 7410 663bc7 740b 83f801 7406 8bee 8b36 }
            // n = 7, score = 100
            //   7410                 | je                  0x12
            //   663bc7               | cmp                 ax, di
            //   740b                 | je                  0xd
            //   83f801               | cmp                 eax, 1
            //   7406                 | je                  8
            //   8bee                 | mov                 ebp, esi
            //   8b36                 | mov                 esi, dword ptr [esi]

        $sequence_9 = { 0f84c4000000 66837c240c01 0f85b8000000 57 8b7c2408 83c708 f644241401 }
            // n = 7, score = 100
            //   0f84c4000000         | je                  0xca
            //   66837c240c01         | cmp                 word ptr [esp + 0xc], 1
            //   0f85b8000000         | jne                 0xbe
            //   57                   | push                edi
            //   8b7c2408             | mov                 edi, dword ptr [esp + 8]
            //   83c708               | add                 edi, 8
            //   f644241401           | test                byte ptr [esp + 0x14], 1

    condition:
        7 of them and filesize < 2260992
}