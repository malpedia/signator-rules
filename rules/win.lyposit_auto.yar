rule win_lyposit_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.lyposit."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lyposit"
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
        $sequence_0 = { 8975d8 8975fc b9???????? e8???????? 50 }
            // n = 5, score = 200
            //   8975d8               | mov                 dword ptr [ebp - 0x28], esi
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   b9????????           |                     
            //   e8????????           |                     
            //   50                   | push                eax

        $sequence_1 = { 52 53 ff75d4 50 ff510c 3bc3 0f8cf1000000 }
            // n = 7, score = 200
            //   52                   | push                edx
            //   53                   | push                ebx
            //   ff75d4               | push                dword ptr [ebp - 0x2c]
            //   50                   | push                eax
            //   ff510c               | call                dword ptr [ecx + 0xc]
            //   3bc3                 | cmp                 eax, ebx
            //   0f8cf1000000         | jl                  0xf7

        $sequence_2 = { 8945c4 8d4de0 51 ff75d0 56 56 50 }
            // n = 7, score = 200
            //   8945c4               | mov                 dword ptr [ebp - 0x3c], eax
            //   8d4de0               | lea                 ecx, dword ptr [ebp - 0x20]
            //   51                   | push                ecx
            //   ff75d0               | push                dword ptr [ebp - 0x30]
            //   56                   | push                esi
            //   56                   | push                esi
            //   50                   | push                eax

        $sequence_3 = { ff75e0 8d8d9cfdffff 8bc3 e8???????? 59 }
            // n = 5, score = 200
            //   ff75e0               | push                dword ptr [ebp - 0x20]
            //   8d8d9cfdffff         | lea                 ecx, dword ptr [ebp - 0x264]
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_4 = { c1e802 2401 8845fe 8bc2 8aca c1e804 }
            // n = 6, score = 200
            //   c1e802               | shr                 eax, 2
            //   2401                 | and                 al, 1
            //   8845fe               | mov                 byte ptr [ebp - 2], al
            //   8bc2                 | mov                 eax, edx
            //   8aca                 | mov                 cl, dl
            //   c1e804               | shr                 eax, 4

        $sequence_5 = { ff5108 c9 c3 55 8bec 83ec20 53 }
            // n = 7, score = 200
            //   ff5108               | call                dword ptr [ecx + 8]
            //   c9                   | leave               
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec20               | sub                 esp, 0x20
            //   53                   | push                ebx

        $sequence_6 = { 3bc7 72e9 ffd6 a3???????? 895dfc ff750c ff7508 }
            // n = 7, score = 200
            //   3bc7                 | cmp                 eax, edi
            //   72e9                 | jb                  0xffffffeb
            //   ffd6                 | call                esi
            //   a3????????           |                     
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_7 = { e8???????? dec9 8945f4 e8???????? }
            // n = 4, score = 200
            //   e8????????           |                     
            //   dec9                 | fmulp               st(1)
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   e8????????           |                     

        $sequence_8 = { 894108 8b471c ff07 c70003000000 8b4704 85c0 74c3 }
            // n = 7, score = 200
            //   894108               | mov                 dword ptr [ecx + 8], eax
            //   8b471c               | mov                 eax, dword ptr [edi + 0x1c]
            //   ff07                 | inc                 dword ptr [edi]
            //   c70003000000         | mov                 dword ptr [eax], 3
            //   8b4704               | mov                 eax, dword ptr [edi + 4]
            //   85c0                 | test                eax, eax
            //   74c3                 | je                  0xffffffc5

        $sequence_9 = { 8d4dd0 51 50 6a21 ff75e0 ff5312 }
            // n = 6, score = 200
            //   8d4dd0               | lea                 ecx, dword ptr [ebp - 0x30]
            //   51                   | push                ecx
            //   50                   | push                eax
            //   6a21                 | push                0x21
            //   ff75e0               | push                dword ptr [ebp - 0x20]
            //   ff5312               | call                dword ptr [ebx + 0x12]

    condition:
        7 of them and filesize < 466944
}