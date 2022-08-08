rule win_recordbreaker_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-08-05"
        version = "1"
        description = "Detects win.recordbreaker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.recordbreaker"
        malpedia_rule_date = "20220805"
        malpedia_hash = "6ec06c64bcfdbeda64eff021c766b4ce34542b71"
        malpedia_version = "20220808"
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
        $sequence_0 = { 8945f0 ffd1 8b0d???????? 68???????? 8945e8 ffd1 8b0d???????? }
            // n = 7, score = 200
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   ffd1                 | call                ecx
            //   8b0d????????         |                     
            //   68????????           |                     
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   ffd1                 | call                ecx
            //   8b0d????????         |                     

        $sequence_1 = { 8b15???????? 8bc8 e8???????? 8b7df4 8bc8 8bd7 e8???????? }
            // n = 7, score = 200
            //   8b15????????         |                     
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   8b7df4               | mov                 edi, dword ptr [ebp - 0xc]
            //   8bc8                 | mov                 ecx, eax
            //   8bd7                 | mov                 edx, edi
            //   e8????????           |                     

        $sequence_2 = { 8b0d???????? 8bf0 57 6a40 ffd1 8b0d???????? 68???????? }
            // n = 7, score = 200
            //   8b0d????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   57                   | push                edi
            //   6a40                 | push                0x40
            //   ffd1                 | call                ecx
            //   8b0d????????         |                     
            //   68????????           |                     

        $sequence_3 = { 56 eb03 ff750c ffd0 8b4df0 8d55f8 33f6 }
            // n = 7, score = 200
            //   56                   | push                esi
            //   eb03                 | jmp                 5
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ffd0                 | call                eax
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   8d55f8               | lea                 edx, [ebp - 8]
            //   33f6                 | xor                 esi, esi

        $sequence_4 = { ff7514 8945d4 ff15???????? 83c418 8bf8 83fe01 }
            // n = 6, score = 200
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax
            //   ff15????????         |                     
            //   83c418               | add                 esp, 0x18
            //   8bf8                 | mov                 edi, eax
            //   83fe01               | cmp                 esi, 1

        $sequence_5 = { 5e eb14 6bf34c 03f7 8b7d0c a5 a5 }
            // n = 7, score = 200
            //   5e                   | pop                 esi
            //   eb14                 | jmp                 0x16
            //   6bf34c               | imul                esi, ebx, 0x4c
            //   03f7                 | add                 esi, edi
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]

        $sequence_6 = { a1???????? 6800002000 6a40 5f 57 ffd0 6800002000 }
            // n = 7, score = 200
            //   a1????????           |                     
            //   6800002000           | push                0x200000
            //   6a40                 | push                0x40
            //   5f                   | pop                 edi
            //   57                   | push                edi
            //   ffd0                 | call                eax
            //   6800002000           | push                0x200000

        $sequence_7 = { 8bec 56 8bf1 85d2 7425 8b450c b9feffff7f }
            // n = 7, score = 200
            //   8bec                 | mov                 ebp, esp
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   85d2                 | test                edx, edx
            //   7425                 | je                  0x27
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   b9feffff7f           | mov                 ecx, 0x7ffffffe

        $sequence_8 = { 8b0d???????? 8bf8 53 6a40 897c2434 ffd1 8d542410 }
            // n = 7, score = 200
            //   8b0d????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   53                   | push                ebx
            //   6a40                 | push                0x40
            //   897c2434             | mov                 dword ptr [esp + 0x34], edi
            //   ffd1                 | call                ecx
            //   8d542410             | lea                 edx, [esp + 0x10]

        $sequence_9 = { 8b7510 85f6 7418 a1???????? 53 56 }
            // n = 6, score = 200
            //   8b7510               | mov                 esi, dword ptr [ebp + 0x10]
            //   85f6                 | test                esi, esi
            //   7418                 | je                  0x1a
            //   a1????????           |                     
            //   53                   | push                ebx
            //   56                   | push                esi

    condition:
        7 of them and filesize < 139264
}