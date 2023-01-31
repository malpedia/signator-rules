rule win_badflick_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.badflick."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.badflick"
        malpedia_rule_date = "20230124"
        malpedia_hash = "2ee0eebba83dce3d019a90519f2f972c0fcf9686"
        malpedia_version = "20230125"
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
        $sequence_0 = { 8d440002 50 0fb64508 50 e8???????? ff750c 8bf0 }
            // n = 7, score = 100
            //   8d440002             | lea                 eax, [eax + eax + 2]
            //   50                   | push                eax
            //   0fb64508             | movzx               eax, byte ptr [ebp + 8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   8bf0                 | mov                 esi, eax

        $sequence_1 = { 59 a3???????? 891d???????? ff750c e8???????? 50 }
            // n = 6, score = 100
            //   59                   | pop                 ecx
            //   a3????????           |                     
            //   891d????????         |                     
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   50                   | push                eax

        $sequence_2 = { 57 ff7510 53 eb13 03f8 3b7d10 741a }
            // n = 7, score = 100
            //   57                   | push                edi
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   53                   | push                ebx
            //   eb13                 | jmp                 0x15
            //   03f8                 | add                 edi, eax
            //   3b7d10               | cmp                 edi, dword ptr [ebp + 0x10]
            //   741a                 | je                  0x1c

        $sequence_3 = { 8d8578fbffff 50 57 ff15???????? 8d8578fbffff 50 ffd6 }
            // n = 7, score = 100
            //   8d8578fbffff         | lea                 eax, [ebp - 0x488]
            //   50                   | push                eax
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8d8578fbffff         | lea                 eax, [ebp - 0x488]
            //   50                   | push                eax
            //   ffd6                 | call                esi

        $sequence_4 = { 68???????? ff7508 ff15???????? 33c9 83c41c }
            // n = 5, score = 100
            //   68????????           |                     
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   33c9                 | xor                 ecx, ecx
            //   83c41c               | add                 esp, 0x1c

        $sequence_5 = { 23c8 51 8975ec e8???????? 59 }
            // n = 5, score = 100
            //   23c8                 | and                 ecx, eax
            //   51                   | push                ecx
            //   8975ec               | mov                 dword ptr [ebp - 0x14], esi
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_6 = { 750d 8d85f8fdffff 50 ff15???????? ff15???????? 5f 5e }
            // n = 7, score = 100
            //   750d                 | jne                 0xf
            //   8d85f8fdffff         | lea                 eax, [ebp - 0x208]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_7 = { dcc9 dec9 dd1c24 ff75e8 68???????? ff7508 ff15???????? }
            // n = 7, score = 100
            //   dcc9                 | fmul                st(1), st(0)
            //   dec9                 | fmulp               st(1)
            //   dd1c24               | fstp                qword ptr [esp]
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   68????????           |                     
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     

        $sequence_8 = { ffd7 53 e8???????? 59 6a00 8d4508 50 }
            // n = 7, score = 100
            //   ffd7                 | call                edi
            //   53                   | push                ebx
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   6a00                 | push                0
            //   8d4508               | lea                 eax, [ebp + 8]
            //   50                   | push                eax

        $sequence_9 = { 8b430d 8945d8 8b4311 8945dc 8b4315 8945e0 }
            // n = 6, score = 100
            //   8b430d               | mov                 eax, dword ptr [ebx + 0xd]
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   8b4311               | mov                 eax, dword ptr [ebx + 0x11]
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   8b4315               | mov                 eax, dword ptr [ebx + 0x15]
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax

    condition:
        7 of them and filesize < 81920
}