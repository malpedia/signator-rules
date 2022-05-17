rule win_milum_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.milum."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.milum"
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
        $sequence_0 = { 1116 1216 1016 16 1314156a30b8ad b245 00e8 }
            // n = 7, score = 400
            //   1116                 | adc                 dword ptr [esi], edx
            //   1216                 | adc                 dl, byte ptr [esi]
            //   1016                 | adc                 byte ptr [esi], dl
            //   16                   | push                ss
            //   1314156a30b8ad       | adc                 edx, dword ptr [edx - 0x5247cf96]
            //   b245                 | mov                 dl, 0x45
            //   00e8                 | add                 al, ch

        $sequence_1 = { e8???????? c78528ffffff01000000 c645fc04 837de410 720c 8b55d0 52 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   c78528ffffff01000000     | mov    dword ptr [ebp - 0xd8], 1
            //   c645fc04             | mov                 byte ptr [ebp - 4], 4
            //   837de410             | cmp                 dword ptr [ebp - 0x1c], 0x10
            //   720c                 | jb                  0xe
            //   8b55d0               | mov                 edx, dword ptr [ebp - 0x30]
            //   52                   | push                edx

        $sequence_2 = { 6a01 56 8bc7 e8???????? 8bc6 8be5 5d }
            // n = 7, score = 400
            //   6a01                 | push                1
            //   56                   | push                esi
            //   8bc7                 | mov                 eax, edi
            //   e8????????           |                     
            //   8bc6                 | mov                 eax, esi
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp

        $sequence_3 = { e8???????? c645fc12 83bd3cffffff10 720f 8b8528ffffff 50 e8???????? }
            // n = 7, score = 400
            //   e8????????           |                     
            //   c645fc12             | mov                 byte ptr [ebp - 4], 0x12
            //   83bd3cffffff10       | cmp                 dword ptr [ebp - 0xc4], 0x10
            //   720f                 | jb                  0x11
            //   8b8528ffffff         | mov                 eax, dword ptr [ebp - 0xd8]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_4 = { 899d28ffffff b90f000000 89b524ffffff 898d48ffffff 899d44ffffff 889d34ffffff c745fc01000000 }
            // n = 7, score = 400
            //   899d28ffffff         | mov                 dword ptr [ebp - 0xd8], ebx
            //   b90f000000           | mov                 ecx, 0xf
            //   89b524ffffff         | mov                 dword ptr [ebp - 0xdc], esi
            //   898d48ffffff         | mov                 dword ptr [ebp - 0xb8], ecx
            //   899d44ffffff         | mov                 dword ptr [ebp - 0xbc], ebx
            //   889d34ffffff         | mov                 byte ptr [ebp - 0xcc], bl
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1

        $sequence_5 = { 50 8d45f4 64a300000000 8b7508 c745fc03000000 8d7e74 897df0 }
            // n = 7, score = 400
            //   50                   | push                eax
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   c745fc03000000       | mov                 dword ptr [ebp - 4], 3
            //   8d7e74               | lea                 edi, [esi + 0x74]
            //   897df0               | mov                 dword ptr [ebp - 0x10], edi

        $sequence_6 = { 5d c3 f6c120 7406 db00 8be5 5d }
            // n = 7, score = 400
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   f6c120               | test                cl, 0x20
            //   7406                 | je                  8
            //   db00                 | fild                dword ptr [eax]
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp

        $sequence_7 = { 66894c241a 8b4d14 8944240c 89442414 89442410 89542414 894c240c }
            // n = 7, score = 400
            //   66894c241a           | mov                 word ptr [esp + 0x1a], cx
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]
            //   8944240c             | mov                 dword ptr [esp + 0xc], eax
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   89542414             | mov                 dword ptr [esp + 0x14], edx
            //   894c240c             | mov                 dword ptr [esp + 0xc], ecx

        $sequence_8 = { 8819 e8???????? c684247c03000010 83ec1c 8bcc 89642450 6aff }
            // n = 7, score = 400
            //   8819                 | mov                 byte ptr [ecx], bl
            //   e8????????           |                     
            //   c684247c03000010     | mov                 byte ptr [esp + 0x37c], 0x10
            //   83ec1c               | sub                 esp, 0x1c
            //   8bcc                 | mov                 ecx, esp
            //   89642450             | mov                 dword ptr [esp + 0x50], esp
            //   6aff                 | push                -1

        $sequence_9 = { 0f86baecffff 5f 5b b8feffffff 5e 8be5 5d }
            // n = 7, score = 400
            //   0f86baecffff         | jbe                 0xffffecc0
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx
            //   b8feffffff           | mov                 eax, 0xfffffffe
            //   5e                   | pop                 esi
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp

    condition:
        7 of them and filesize < 1076224
}