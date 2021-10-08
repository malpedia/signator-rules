rule win_keylogger_apt3_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2021-10-07"
        version = "1"
        description = "Detects win.keylogger_apt3."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.keylogger_apt3"
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
        $sequence_0 = { 57 3bf3 7405 395d0c 7720 }
            // n = 5, score = 300
            //   57                   | push                edi
            //   3bf3                 | cmp                 esi, ebx
            //   7405                 | je                  7
            //   395d0c               | cmp                 dword ptr [ebp + 0xc], ebx
            //   7720                 | ja                  0x22

        $sequence_1 = { 6689542434 e8???????? 56 6a28 }
            // n = 4, score = 300
            //   6689542434           | mov                 word ptr [esp + 0x34], dx
            //   e8????????           |                     
            //   56                   | push                esi
            //   6a28                 | push                0x28

        $sequence_2 = { 7e15 ba???????? 90 3a02 740b }
            // n = 5, score = 300
            //   7e15                 | jle                 0x17
            //   ba????????           |                     
            //   90                   | nop                 
            //   3a02                 | cmp                 al, byte ptr [edx]
            //   740b                 | je                  0xd

        $sequence_3 = { 2bc2 8bf8 b134 b033 33f6 }
            // n = 5, score = 300
            //   2bc2                 | sub                 eax, edx
            //   8bf8                 | mov                 edi, eax
            //   b134                 | mov                 cl, 0x34
            //   b033                 | mov                 al, 0x33
            //   33f6                 | xor                 esi, esi

        $sequence_4 = { 8810 897008 897010 89700c 0514010000 03cf }
            // n = 6, score = 300
            //   8810                 | mov                 byte ptr [eax], dl
            //   897008               | mov                 dword ptr [eax + 8], esi
            //   897010               | mov                 dword ptr [eax + 0x10], esi
            //   89700c               | mov                 dword ptr [eax + 0xc], esi
            //   0514010000           | add                 eax, 0x114
            //   03cf                 | add                 ecx, edi

        $sequence_5 = { ffd7 8b15???????? 8d4c2428 51 }
            // n = 4, score = 300
            //   ffd7                 | call                edi
            //   8b15????????         |                     
            //   8d4c2428             | lea                 ecx, dword ptr [esp + 0x28]
            //   51                   | push                ecx

        $sequence_6 = { e8???????? 8b74244c 8bf8 83c430 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   8b74244c             | mov                 esi, dword ptr [esp + 0x4c]
            //   8bf8                 | mov                 edi, eax
            //   83c430               | add                 esp, 0x30

        $sequence_7 = { 51 52 e8???????? 8b7604 682000cc00 6a00 }
            // n = 6, score = 300
            //   51                   | push                ecx
            //   52                   | push                edx
            //   e8????????           |                     
            //   8b7604               | mov                 esi, dword ptr [esi + 4]
            //   682000cc00           | push                0xcc0020
            //   6a00                 | push                0

        $sequence_8 = { 50 eb0c 8b15???????? 8d4c2408 51 }
            // n = 5, score = 300
            //   50                   | push                eax
            //   eb0c                 | jmp                 0xe
            //   8b15????????         |                     
            //   8d4c2408             | lea                 ecx, dword ptr [esp + 8]
            //   51                   | push                ecx

        $sequence_9 = { e8???????? 83c438 837c241800 c744241c00000000 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   83c438               | add                 esp, 0x38
            //   837c241800           | cmp                 dword ptr [esp + 0x18], 0
            //   c744241c00000000     | mov                 dword ptr [esp + 0x1c], 0

    condition:
        7 of them and filesize < 761856
}