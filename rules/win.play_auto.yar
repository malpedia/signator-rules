rule win_play_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.play."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.play"
        malpedia_rule_date = "20221118"
        malpedia_hash = "e0702e2e6d1d00da65c8a29a4ebacd0a4c59e1af"
        malpedia_version = "20221125"
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
        $sequence_0 = { 8885affdffff 8a852cfdffff 8885b0fdffff 8a8529fdffff 8885aefdffff 668b8534fdffff 668985a2fdffff }
            // n = 7, score = 100
            //   8885affdffff         | mov                 byte ptr [ebp - 0x251], al
            //   8a852cfdffff         | mov                 al, byte ptr [ebp - 0x2d4]
            //   8885b0fdffff         | mov                 byte ptr [ebp - 0x250], al
            //   8a8529fdffff         | mov                 al, byte ptr [ebp - 0x2d7]
            //   8885aefdffff         | mov                 byte ptr [ebp - 0x252], al
            //   668b8534fdffff       | mov                 ax, word ptr [ebp - 0x2cc]
            //   668985a2fdffff       | mov                 word ptr [ebp - 0x25e], ax

        $sequence_1 = { ff15???????? 83f809 7513 0fb645e9 0527130000 50 ff15???????? }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   83f809               | cmp                 eax, 9
            //   7513                 | jne                 0x15
            //   0fb645e9             | movzx               eax, byte ptr [ebp - 0x17]
            //   0527130000           | add                 eax, 0x1327
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_2 = { 90 40 02ca 3dd5040000 72f6 8b5d08 }
            // n = 6, score = 100
            //   90                   | nop                 
            //   40                   | inc                 eax
            //   02ca                 | add                 cl, dl
            //   3dd5040000           | cmp                 eax, 0x4d5
            //   72f6                 | jb                  0xfffffff8
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]

        $sequence_3 = { 0fb6cd 83f968 7612 8a55da }
            // n = 4, score = 100
            //   0fb6cd               | movzx               ecx, ch
            //   83f968               | cmp                 ecx, 0x68
            //   7612                 | jbe                 0x14
            //   8a55da               | mov                 dl, byte ptr [ebp - 0x26]

        $sequence_4 = { 3bc2 7f06 81c4c5010000 83c40c e8???????? 9e }
            // n = 6, score = 100
            //   3bc2                 | cmp                 eax, edx
            //   7f06                 | jg                  8
            //   81c4c5010000         | add                 esp, 0x1c5
            //   83c40c               | add                 esp, 0xc
            //   e8????????           |                     
            //   9e                   | sahf                

        $sequence_5 = { 0fb685d2feffff 89856cfeffff 03d8 e8???????? 8a85cbfeffff b9???????? fec0 }
            // n = 7, score = 100
            //   0fb685d2feffff       | movzx               eax, byte ptr [ebp - 0x12e]
            //   89856cfeffff         | mov                 dword ptr [ebp - 0x194], eax
            //   03d8                 | add                 ebx, eax
            //   e8????????           |                     
            //   8a85cbfeffff         | mov                 al, byte ptr [ebp - 0x135]
            //   b9????????           |                     
            //   fec0                 | inc                 al

        $sequence_6 = { 8955e8 0fb6543104 8b4df4 c1e208 0fb64c3104 0bd1 8b4df0 }
            // n = 7, score = 100
            //   8955e8               | mov                 dword ptr [ebp - 0x18], edx
            //   0fb6543104           | movzx               edx, byte ptr [ecx + esi + 4]
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   c1e208               | shl                 edx, 8
            //   0fb64c3104           | movzx               ecx, byte ptr [ecx + esi + 4]
            //   0bd1                 | or                  edx, ecx
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]

        $sequence_7 = { 83042436 c3 aa 0030 85b7a34a892f 59 6d }
            // n = 7, score = 100
            //   83042436             | add                 dword ptr [esp], 0x36
            //   c3                   | ret                 
            //   aa                   | stosb               byte ptr es:[edi], al
            //   0030                 | add                 byte ptr [eax], dh
            //   85b7a34a892f         | test                dword ptr [edi + 0x2f894aa3], esi
            //   59                   | pop                 ecx
            //   6d                   | insd                dword ptr es:[edi], dx

        $sequence_8 = { ce e0fd 9c 43 5b f5 ae }
            // n = 7, score = 100
            //   ce                   | into                
            //   e0fd                 | loopne              0xffffffff
            //   9c                   | pushfd              
            //   43                   | inc                 ebx
            //   5b                   | pop                 ebx
            //   f5                   | cmc                 
            //   ae                   | scasb               al, byte ptr es:[edi]

        $sequence_9 = { 0f854c010000 b890000000 8b0c02 85c9 0f8430010000 837c020400 0f8425010000 }
            // n = 7, score = 100
            //   0f854c010000         | jne                 0x152
            //   b890000000           | mov                 eax, 0x90
            //   8b0c02               | mov                 ecx, dword ptr [edx + eax]
            //   85c9                 | test                ecx, ecx
            //   0f8430010000         | je                  0x136
            //   837c020400           | cmp                 dword ptr [edx + eax + 4], 0
            //   0f8425010000         | je                  0x12b

    condition:
        7 of them and filesize < 389120
}