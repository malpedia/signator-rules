rule win_yoddos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.yoddos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.yoddos"
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
        $sequence_0 = { c1e604 aa 8d9e805c4100 803b00 8bcb 742c 8a5101 }
            // n = 7, score = 100
            //   c1e604               | shl                 esi, 4
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8d9e805c4100         | lea                 ebx, [esi + 0x415c80]
            //   803b00               | cmp                 byte ptr [ebx], 0
            //   8bcb                 | mov                 ecx, ebx
            //   742c                 | je                  0x2e
            //   8a5101               | mov                 dl, byte ptr [ecx + 1]

        $sequence_1 = { ffd6 6689850aedffff 8d4708 50 ffd6 6689850cedffff 66899d0eedffff }
            // n = 7, score = 100
            //   ffd6                 | call                esi
            //   6689850aedffff       | mov                 word ptr [ebp - 0x12f6], ax
            //   8d4708               | lea                 eax, [edi + 8]
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   6689850cedffff       | mov                 word ptr [ebp - 0x12f4], ax
            //   66899d0eedffff       | mov                 word ptr [ebp - 0x12f2], bx

        $sequence_2 = { 8bc8 85c9 7d18 ff7508 ff15???????? 85c0 }
            // n = 6, score = 100
            //   8bc8                 | mov                 ecx, eax
            //   85c9                 | test                ecx, ecx
            //   7d18                 | jge                 0x1a
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_3 = { 83c40c 46 3bf7 7cdd 8d85eceeffff 50 }
            // n = 6, score = 100
            //   83c40c               | add                 esp, 0xc
            //   46                   | inc                 esi
            //   3bf7                 | cmp                 esi, edi
            //   7cdd                 | jl                  0xffffffdf
            //   8d85eceeffff         | lea                 eax, [ebp - 0x1114]
            //   50                   | push                eax

        $sequence_4 = { 68???????? ff955cffffff e9???????? 55 8bec 81ecd4010000 53 }
            // n = 7, score = 100
            //   68????????           |                     
            //   ff955cffffff         | call                dword ptr [ebp - 0xa4]
            //   e9????????           |                     
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ecd4010000         | sub                 esp, 0x1d4
            //   53                   | push                ebx

        $sequence_5 = { 898568fdffff 8d45b0 89856cfdffff 8d8550feffff 898570fdffff 8d8570ffffff }
            // n = 6, score = 100
            //   898568fdffff         | mov                 dword ptr [ebp - 0x298], eax
            //   8d45b0               | lea                 eax, [ebp - 0x50]
            //   89856cfdffff         | mov                 dword ptr [ebp - 0x294], eax
            //   8d8550feffff         | lea                 eax, [ebp - 0x1b0]
            //   898570fdffff         | mov                 dword ptr [ebp - 0x290], eax
            //   8d8570ffffff         | lea                 eax, [ebp - 0x90]

        $sequence_6 = { b863000000 90 b89dffffff 90 8d8588fdffff 50 8d8584fcffff }
            // n = 7, score = 100
            //   b863000000           | mov                 eax, 0x63
            //   90                   | nop                 
            //   b89dffffff           | mov                 eax, 0xffffff9d
            //   90                   | nop                 
            //   8d8588fdffff         | lea                 eax, [ebp - 0x278]
            //   50                   | push                eax
            //   8d8584fcffff         | lea                 eax, [ebp - 0x37c]

        $sequence_7 = { 751a ff15???????? ff7608 894604 ff15???????? 83660800 33c0 }
            // n = 7, score = 100
            //   751a                 | jne                 0x1c
            //   ff15????????         |                     
            //   ff7608               | push                dword ptr [esi + 8]
            //   894604               | mov                 dword ptr [esi + 4], eax
            //   ff15????????         |                     
            //   83660800             | and                 dword ptr [esi + 8], 0
            //   33c0                 | xor                 eax, eax

        $sequence_8 = { 5e 5b b863000000 90 b89dffffff 90 }
            // n = 6, score = 100
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   b863000000           | mov                 eax, 0x63
            //   90                   | nop                 
            //   b89dffffff           | mov                 eax, 0xffffff9d
            //   90                   | nop                 

        $sequence_9 = { 8b0c8d00764100 8d54c104 8a4cc104 f6c101 743e }
            // n = 5, score = 100
            //   8b0c8d00764100       | mov                 ecx, dword ptr [ecx*4 + 0x417600]
            //   8d54c104             | lea                 edx, [ecx + eax*8 + 4]
            //   8a4cc104             | mov                 cl, byte ptr [ecx + eax*8 + 4]
            //   f6c101               | test                cl, 1
            //   743e                 | je                  0x40

    condition:
        7 of them and filesize < 557056
}