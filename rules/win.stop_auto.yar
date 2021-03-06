rule win_stop_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.stop."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stop"
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
        $sequence_0 = { 6a00 56 e8???????? 83c40c 8bce ff7508 }
            // n = 6, score = 400
            //   6a00                 | push                0
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8bce                 | mov                 ecx, esi
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_1 = { 66894628 837e2408 720b ff7610 }
            // n = 4, score = 400
            //   66894628             | mov                 word ptr [esi + 0x28], ax
            //   837e2408             | cmp                 dword ptr [esi + 0x24], 8
            //   720b                 | jb                  0xd
            //   ff7610               | push                dword ptr [esi + 0x10]

        $sequence_2 = { 8bf1 56 6a00 ff7508 68???????? 6a00 6a00 }
            // n = 7, score = 400
            //   8bf1                 | mov                 esi, ecx
            //   56                   | push                esi
            //   6a00                 | push                0
            //   ff7508               | push                dword ptr [ebp + 8]
            //   68????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_3 = { ffd6 85c0 75e2 6a64 ff15???????? ffd3 }
            // n = 6, score = 400
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   75e2                 | jne                 0xffffffe4
            //   6a64                 | push                0x64
            //   ff15????????         |                     
            //   ffd3                 | call                ebx

        $sequence_4 = { 6800040000 57 6a00 ff15???????? }
            // n = 4, score = 400
            //   6800040000           | push                0x400
            //   57                   | push                edi
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_5 = { 83c404 33c0 c7463c07000000 c7463800000000 66894628 837e2408 }
            // n = 6, score = 400
            //   83c404               | add                 esp, 4
            //   33c0                 | xor                 eax, eax
            //   c7463c07000000       | mov                 dword ptr [esi + 0x3c], 7
            //   c7463800000000       | mov                 dword ptr [esi + 0x38], 0
            //   66894628             | mov                 word ptr [esi + 0x28], ax
            //   837e2408             | cmp                 dword ptr [esi + 0x24], 8

        $sequence_6 = { 50 ff15???????? 8bf8 85ff 790f }
            // n = 5, score = 400
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi
            //   790f                 | jns                 0x11

        $sequence_7 = { 8bd9 6a00 6a12 ff33 ff15???????? }
            // n = 5, score = 400
            //   8bd9                 | mov                 ebx, ecx
            //   6a00                 | push                0
            //   6a12                 | push                0x12
            //   ff33                 | push                dword ptr [ebx]
            //   ff15????????         |                     

        $sequence_8 = { 83c404 8b4b04 b8abaaaa2a 2b0b }
            // n = 4, score = 400
            //   83c404               | add                 esp, 4
            //   8b4b04               | mov                 ecx, dword ptr [ebx + 4]
            //   b8abaaaa2a           | mov                 eax, 0x2aaaaaab
            //   2b0b                 | sub                 ecx, dword ptr [ebx]

        $sequence_9 = { 8b35???????? 8b3d???????? 6a01 6a00 6a00 6a00 }
            // n = 6, score = 400
            //   8b35????????         |                     
            //   8b3d????????         |                     
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0

    condition:
        7 of them and filesize < 6029312
}