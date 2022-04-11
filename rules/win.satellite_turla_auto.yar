rule win_satellite_turla_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.satellite_turla."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.satellite_turla"
        malpedia_rule_date = "20220405"
        malpedia_hash = "ecd38294bd47d5589be5cd5490dc8bb4804afc2a"
        malpedia_version = ""
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
        $sequence_0 = { 0105???????? 81c3b0020000 2945e0 75ae 837dd400 }
            // n = 5, score = 200
            //   0105????????         |                     
            //   81c3b0020000         | add                 ebx, 0x2b0
            //   2945e0               | sub                 dword ptr [ebp - 0x20], eax
            //   75ae                 | jne                 0xffffffb0
            //   837dd400             | cmp                 dword ptr [ebp - 0x2c], 0

        $sequence_1 = { 0108 833e00 7fc7 db46fc }
            // n = 4, score = 200
            //   0108                 | add                 dword ptr [eax], ecx
            //   833e00               | cmp                 dword ptr [esi], 0
            //   7fc7                 | jg                  0xffffffc9
            //   db46fc               | fild                dword ptr [esi - 4]

        $sequence_2 = { 0105???????? 83c410 29442418 75a9 }
            // n = 4, score = 200
            //   0105????????         |                     
            //   83c410               | add                 esp, 0x10
            //   29442418             | sub                 dword ptr [esp + 0x18], eax
            //   75a9                 | jne                 0xffffffab

        $sequence_3 = { 0105???????? 83c410 29442420 75aa }
            // n = 4, score = 200
            //   0105????????         |                     
            //   83c410               | add                 esp, 0x10
            //   29442420             | sub                 dword ptr [esp + 0x20], eax
            //   75aa                 | jne                 0xffffffac

        $sequence_4 = { 0108 833a00 7c23 8b442428 }
            // n = 4, score = 200
            //   0108                 | add                 dword ptr [eax], ecx
            //   833a00               | cmp                 dword ptr [edx], 0
            //   7c23                 | jl                  0x25
            //   8b442428             | mov                 eax, dword ptr [esp + 0x28]

        $sequence_5 = { 0108 833e00 7c1f 8b542410 }
            // n = 4, score = 200
            //   0108                 | add                 dword ptr [eax], ecx
            //   833e00               | cmp                 dword ptr [esi], 0
            //   7c1f                 | jl                  0x21
            //   8b542410             | mov                 edx, dword ptr [esp + 0x10]

        $sequence_6 = { 51 8d9424c4030000 68???????? 52 ff15???????? }
            // n = 5, score = 200
            //   51                   | push                ecx
            //   8d9424c4030000       | lea                 edx, dword ptr [esp + 0x3c4]
            //   68????????           |                     
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_7 = { 0108 833e00 7cc7 7e39 }
            // n = 4, score = 200
            //   0108                 | add                 dword ptr [eax], ecx
            //   833e00               | cmp                 dword ptr [esi], 0
            //   7cc7                 | jl                  0xffffffc9
            //   7e39                 | jle                 0x3b

        $sequence_8 = { 56 ff15???????? 56 56 56 56 ff15???????? }
            // n = 7, score = 100
            //   56                   | push                esi
            //   ff15????????         |                     
            //   56                   | push                esi
            //   56                   | push                esi
            //   56                   | push                esi
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_9 = { 56 56 ffd7 56 56 ff15???????? }
            // n = 6, score = 100
            //   56                   | push                esi
            //   56                   | push                esi
            //   ffd7                 | call                edi
            //   56                   | push                esi
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_10 = { 885dcf 50 57 ffd6 a3???????? 6a0d }
            // n = 6, score = 100
            //   885dcf               | mov                 byte ptr [ebp - 0x31], bl
            //   50                   | push                eax
            //   57                   | push                edi
            //   ffd6                 | call                esi
            //   a3????????           |                     
            //   6a0d                 | push                0xd

        $sequence_11 = { a3???????? c645f41f c645f53a c645f621 }
            // n = 4, score = 100
            //   a3????????           |                     
            //   c645f41f             | mov                 byte ptr [ebp - 0xc], 0x1f
            //   c645f53a             | mov                 byte ptr [ebp - 0xb], 0x3a
            //   c645f621             | mov                 byte ptr [ebp - 0xa], 0x21

        $sequence_12 = { 50 e8???????? 83c40c 8d45f4 885dfd 50 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d45f4               | lea                 eax, dword ptr [ebp - 0xc]
            //   885dfd               | mov                 byte ptr [ebp - 3], bl
            //   50                   | push                eax

        $sequence_13 = { c645f82d c645f90e c645fa21 c645fb24 c645fc2d c645fd2d 6a48 }
            // n = 7, score = 100
            //   c645f82d             | mov                 byte ptr [ebp - 8], 0x2d
            //   c645f90e             | mov                 byte ptr [ebp - 7], 0xe
            //   c645fa21             | mov                 byte ptr [ebp - 6], 0x21
            //   c645fb24             | mov                 byte ptr [ebp - 5], 0x24
            //   c645fc2d             | mov                 byte ptr [ebp - 4], 0x2d
            //   c645fd2d             | mov                 byte ptr [ebp - 3], 0x2d
            //   6a48                 | push                0x48

        $sequence_14 = { c6459c1f c6459d1f c6459e19 c6459f02 }
            // n = 4, score = 100
            //   c6459c1f             | mov                 byte ptr [ebp - 0x64], 0x1f
            //   c6459d1f             | mov                 byte ptr [ebp - 0x63], 0x1f
            //   c6459e19             | mov                 byte ptr [ebp - 0x62], 0x19
            //   c6459f02             | mov                 byte ptr [ebp - 0x61], 2

        $sequence_15 = { c645e544 c645e64d c645e74d e8???????? }
            // n = 4, score = 100
            //   c645e544             | mov                 byte ptr [ebp - 0x1b], 0x44
            //   c645e64d             | mov                 byte ptr [ebp - 0x1a], 0x4d
            //   c645e74d             | mov                 byte ptr [ebp - 0x19], 0x4d
            //   e8????????           |                     

    condition:
        7 of them and filesize < 1040384
}