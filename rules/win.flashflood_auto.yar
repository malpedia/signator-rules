rule win_flashflood_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.flashflood."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.flashflood"
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
        $sequence_0 = { 8bf0 83feff 745f 8d85c0f9ffff }
            // n = 4, score = 100
            //   8bf0                 | mov                 esi, eax
            //   83feff               | cmp                 esi, -1
            //   745f                 | je                  0x61
            //   8d85c0f9ffff         | lea                 eax, dword ptr [ebp - 0x640]

        $sequence_1 = { 8945fc 0f8495010000 bb???????? bf???????? 80bd68feffff2e 0f844f010000 }
            // n = 6, score = 100
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   0f8495010000         | je                  0x19b
            //   bb????????           |                     
            //   bf????????           |                     
            //   80bd68feffff2e       | cmp                 byte ptr [ebp - 0x198], 0x2e
            //   0f844f010000         | je                  0x155

        $sequence_2 = { 33d2 894508 8bc6 f7f1 85d2 7403 ff4508 }
            // n = 7, score = 100
            //   33d2                 | xor                 edx, edx
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   8bc6                 | mov                 eax, esi
            //   f7f1                 | div                 ecx
            //   85d2                 | test                edx, edx
            //   7403                 | je                  5
            //   ff4508               | inc                 dword ptr [ebp + 8]

        $sequence_3 = { 817df000ca9a3b 7303 832300 33db }
            // n = 4, score = 100
            //   817df000ca9a3b       | cmp                 dword ptr [ebp - 0x10], 0x3b9aca00
            //   7303                 | jae                 5
            //   832300               | and                 dword ptr [ebx], 0
            //   33db                 | xor                 ebx, ebx

        $sequence_4 = { ffd6 53 ff75fc 6a01 }
            // n = 4, score = 100
            //   ffd6                 | call                esi
            //   53                   | push                ebx
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   6a01                 | push                1

        $sequence_5 = { ff15???????? 8d85f0f9ffff 50 8d85f0fbffff }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   8d85f0f9ffff         | lea                 eax, dword ptr [ebp - 0x610]
            //   50                   | push                eax
            //   8d85f0fbffff         | lea                 eax, dword ptr [ebp - 0x410]

        $sequence_6 = { 8b5508 898ab4160000 e9???????? 8b45f4 33c9 8a88b09a4000 894df0 }
            // n = 7, score = 100
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   898ab4160000         | mov                 dword ptr [edx + 0x16b4], ecx
            //   e9????????           |                     
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   33c9                 | xor                 ecx, ecx
            //   8a88b09a4000         | mov                 cl, byte ptr [eax + 0x409ab0]
            //   894df0               | mov                 dword ptr [ebp - 0x10], ecx

        $sequence_7 = { 8b0c85d8924000 894dfc 837dfc00 0f842d010000 8b55f0 }
            // n = 5, score = 100
            //   8b0c85d8924000       | mov                 ecx, dword ptr [eax*4 + 0x4092d8]
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0
            //   0f842d010000         | je                  0x133
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]

        $sequence_8 = { c9 c3 56 68???????? ff74240c ff15???????? 8bf0 }
            // n = 7, score = 100
            //   c9                   | leave               
            //   c3                   | ret                 
            //   56                   | push                esi
            //   68????????           |                     
            //   ff74240c             | push                dword ptr [esp + 0xc]
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_9 = { 8d85a8faffff 50 ff15???????? 8bf8 83ffff 0f84c4000000 }
            // n = 6, score = 100
            //   8d85a8faffff         | lea                 eax, dword ptr [ebp - 0x558]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   83ffff               | cmp                 edi, -1
            //   0f84c4000000         | je                  0xca

    condition:
        7 of them and filesize < 114688
}