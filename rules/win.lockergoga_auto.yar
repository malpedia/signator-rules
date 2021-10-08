rule win_lockergoga_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.lockergoga."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lockergoga"
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
        $sequence_0 = { eb33 83fb20 7707 b820000000 eb27 83fb40 7707 }
            // n = 7, score = 400
            //   eb33                 | jmp                 0x35
            //   83fb20               | cmp                 ebx, 0x20
            //   7707                 | ja                  9
            //   b820000000           | mov                 eax, 0x20
            //   eb27                 | jmp                 0x29
            //   83fb40               | cmp                 ebx, 0x40
            //   7707                 | ja                  9

        $sequence_1 = { ffd2 84c0 7409 b001 b901000000 eb04 32c0 }
            // n = 7, score = 400
            //   ffd2                 | call                edx
            //   84c0                 | test                al, al
            //   7409                 | je                  0xb
            //   b001                 | mov                 al, 1
            //   b901000000           | mov                 ecx, 1
            //   eb04                 | jmp                 6
            //   32c0                 | xor                 al, al

        $sequence_2 = { e8???????? 8b7584 8b4580 8b4854 2b4850 b8abaaaa2a f7e9 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   8b7584               | mov                 esi, dword ptr [ebp - 0x7c]
            //   8b4580               | mov                 eax, dword ptr [ebp - 0x80]
            //   8b4854               | mov                 ecx, dword ptr [eax + 0x54]
            //   2b4850               | sub                 ecx, dword ptr [eax + 0x50]
            //   b8abaaaa2a           | mov                 eax, 0x2aaaaaab
            //   f7e9                 | imul                ecx

        $sequence_3 = { ff10 8d4b10 e8???????? 6a38 53 e8???????? 83c408 }
            // n = 7, score = 400
            //   ff10                 | call                dword ptr [eax]
            //   8d4b10               | lea                 ecx, dword ptr [ebx + 0x10]
            //   e8????????           |                     
            //   6a38                 | push                0x38
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_4 = { 8d0439 3bd8 7270 8bc7 8945ac 90 8b5640 }
            // n = 7, score = 400
            //   8d0439               | lea                 eax, dword ptr [ecx + edi]
            //   3bd8                 | cmp                 ebx, eax
            //   7270                 | jb                  0x72
            //   8bc7                 | mov                 eax, edi
            //   8945ac               | mov                 dword ptr [ebp - 0x54], eax
            //   90                   | nop                 
            //   8b5640               | mov                 edx, dword ptr [esi + 0x40]

        $sequence_5 = { 8955a8 899560ffffff 897dac 89bd64ffffff 894580 898568ffffff 8b06 }
            // n = 7, score = 400
            //   8955a8               | mov                 dword ptr [ebp - 0x58], edx
            //   899560ffffff         | mov                 dword ptr [ebp - 0xa0], edx
            //   897dac               | mov                 dword ptr [ebp - 0x54], edi
            //   89bd64ffffff         | mov                 dword ptr [ebp - 0x9c], edi
            //   894580               | mov                 dword ptr [ebp - 0x80], eax
            //   898568ffffff         | mov                 dword ptr [ebp - 0x98], eax
            //   8b06                 | mov                 eax, dword ptr [esi]

        $sequence_6 = { 8b4e04 83c404 89040b 8b4e04 8b0c0b 8bd7 8b45d4 }
            // n = 7, score = 400
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   83c404               | add                 esp, 4
            //   89040b               | mov                 dword ptr [ebx + ecx], eax
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   8b0c0b               | mov                 ecx, dword ptr [ebx + ecx]
            //   8bd7                 | mov                 edx, edi
            //   8b45d4               | mov                 eax, dword ptr [ebp - 0x2c]

        $sequence_7 = { 834610ff 7507 c7460c00000000 83ef01 75ee 8b06 33c9 }
            // n = 7, score = 400
            //   834610ff             | add                 dword ptr [esi + 0x10], -1
            //   7507                 | jne                 9
            //   c7460c00000000       | mov                 dword ptr [esi + 0xc], 0
            //   83ef01               | sub                 edi, 1
            //   75ee                 | jne                 0xfffffff0
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   33c9                 | xor                 ecx, ecx

        $sequence_8 = { e8???????? 8bf8 8bce 83ffff 745b 8d47fe 50 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   8bce                 | mov                 ecx, esi
            //   83ffff               | cmp                 edi, -1
            //   745b                 | je                  0x5d
            //   8d47fe               | lea                 eax, dword ptr [edi - 2]
            //   50                   | push                eax

        $sequence_9 = { 8b7dc0 8d4588 50 397dc4 740f 8bcf e8???????? }
            // n = 7, score = 400
            //   8b7dc0               | mov                 edi, dword ptr [ebp - 0x40]
            //   8d4588               | lea                 eax, dword ptr [ebp - 0x78]
            //   50                   | push                eax
            //   397dc4               | cmp                 dword ptr [ebp - 0x3c], edi
            //   740f                 | je                  0x11
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     

    condition:
        7 of them and filesize < 2588672
}