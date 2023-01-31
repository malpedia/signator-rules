rule win_goopic_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.goopic."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.goopic"
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
        $sequence_0 = { ff742420 ff15???????? ff74240c ff15???????? 6a00 6a00 }
            // n = 6, score = 100
            //   ff742420             | push                dword ptr [esp + 0x20]
            //   ff15????????         |                     
            //   ff74240c             | push                dword ptr [esp + 0xc]
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_1 = { ff742430 50 8b08 ff5160 8b442410 8d942490000000 52 }
            // n = 7, score = 100
            //   ff742430             | push                dword ptr [esp + 0x30]
            //   50                   | push                eax
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   ff5160               | call                dword ptr [ecx + 0x60]
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   8d942490000000       | lea                 edx, [esp + 0x90]
            //   52                   | push                edx

        $sequence_2 = { 57 ff15???????? 83bdf0efffff00 7409 }
            // n = 4, score = 100
            //   57                   | push                edi
            //   ff15????????         |                     
            //   83bdf0efffff00       | cmp                 dword ptr [ebp - 0x1010], 0
            //   7409                 | je                  0xb

        $sequence_3 = { ff15???????? 8bd7 8d8df8bfffff e8???????? 57 68???????? }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   8bd7                 | mov                 edx, edi
            //   8d8df8bfffff         | lea                 ecx, [ebp - 0x4008]
            //   e8????????           |                     
            //   57                   | push                edi
            //   68????????           |                     

        $sequence_4 = { 6a00 68???????? 8d85f8efffff 50 }
            // n = 4, score = 100
            //   6a00                 | push                0
            //   68????????           |                     
            //   8d85f8efffff         | lea                 eax, [ebp - 0x1008]
            //   50                   | push                eax

        $sequence_5 = { 6a00 ff15???????? b801000000 5e 5d }
            // n = 5, score = 100
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   b801000000           | mov                 eax, 1
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp

        $sequence_6 = { 8bec 83e4f0 81ecac000000 a1???????? 33c4 898424a8000000 56 }
            // n = 7, score = 100
            //   8bec                 | mov                 ebp, esp
            //   83e4f0               | and                 esp, 0xfffffff0
            //   81ecac000000         | sub                 esp, 0xac
            //   a1????????           |                     
            //   33c4                 | xor                 eax, esp
            //   898424a8000000       | mov                 dword ptr [esp + 0xa8], eax
            //   56                   | push                esi

        $sequence_7 = { 68???????? ff35???????? ffd3 85c0 7517 68c0270900 }
            // n = 6, score = 100
            //   68????????           |                     
            //   ff35????????         |                     
            //   ffd3                 | call                ebx
            //   85c0                 | test                eax, eax
            //   7517                 | jne                 0x19
            //   68c0270900           | push                0x927c0

        $sequence_8 = { 8bf8 85ff 0f84b3000000 8b35???????? 6a00 ffb5f4efffff ffd6 }
            // n = 7, score = 100
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi
            //   0f84b3000000         | je                  0xb9
            //   8b35????????         |                     
            //   6a00                 | push                0
            //   ffb5f4efffff         | push                dword ptr [ebp - 0x100c]
            //   ffd6                 | call                esi

        $sequence_9 = { 53 8983b0000000 ffb5e0efffff ff15???????? ffb5e0efffff }
            // n = 5, score = 100
            //   53                   | push                ebx
            //   8983b0000000         | mov                 dword ptr [ebx + 0xb0], eax
            //   ffb5e0efffff         | push                dword ptr [ebp - 0x1020]
            //   ff15????????         |                     
            //   ffb5e0efffff         | push                dword ptr [ebp - 0x1020]

    condition:
        7 of them and filesize < 114688
}